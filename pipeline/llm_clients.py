"""Unified LLM clients for multi-model vulnerability detection and repair experiments.

Every model, local or hosted, is wrapped behind the same small interface so the
experiment runner can treat them identically:

    client = build_client(model_spec)
    result = client.generate(messages, max_tokens=1024, temperature=0.0)
    client.close()

Supported providers (``provider`` field of a model spec):

- ``hf_local``           Hugging Face model on the local GPU/CPU (optionally 4-bit).
- ``openai``             OpenAI Chat Completions API.
- ``openai_compatible``  Any OpenAI-compatible server (Ollama, vLLM, LM Studio, ...).
- ``anthropic``          Anthropic Messages API.
- ``gemini``             Google Gemini generateContent API.
- ``oracle`` / ``identity``  Built-in sanity models (no network, no GPU). The
  runner gives them the reference fix / the unchanged vulnerable code, so they
  should score ~100% and ~0% exploit-blocked respectively. Use them to verify
  the evaluation pipeline before trusting numbers for real models.

API clients use only the Python standard library (urllib) so no vendor SDKs
are required. API keys are read from environment variables named in the spec
(never stored in config files or results).
"""

from dataclasses import dataclass, field
import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

Message = Dict[str, str]  # {"role": "system"|"user"|"assistant", "content": str}


class LLMClientError(Exception):
    """Raised when a client cannot be created or a request permanently fails."""


@dataclass
class GenerationResult:
    text: str
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_seconds: float = 0.0
    finish_reason: str = "stop"  # "stop", "length", "error"
    error: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


class LLMClient:
    """Base interface."""

    provider = "base"
    supports_prefill = False

    def __init__(self, spec: Dict[str, Any]) -> None:
        self.spec = spec
        self.name: str = spec.get("name") or spec.get("model", "unnamed")
        self.model: str = spec.get("model", "")

    def generate(
        self,
        messages: List[Message],
        max_tokens: int,
        temperature: float = 0.0,
        response_prefix: str = "",
        stop_on_json_close: bool = False,
        context: Optional[Dict[str, Any]] = None,
    ) -> GenerationResult:
        raise NotImplementedError

    def count_tokens(self, text: str) -> int:
        """Approximate token count (used only for logging / budget checks)."""
        return max(1, len(text) // 4)

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------- #
# Sanity models
# --------------------------------------------------------------------------- #

class OracleClient(LLMClient):
    """Returns the answer supplied by the runner in ``context['oracle_answer']``."""

    provider = "oracle"

    def generate(self, messages, max_tokens, temperature=0.0, response_prefix="",
                 stop_on_json_close=False, context=None) -> GenerationResult:
        answer = (context or {}).get("oracle_answer", "")
        return GenerationResult(text=answer, prompt_tokens=0, completion_tokens=0)


class IdentityClient(OracleClient):
    """Returns ``context['identity_answer']`` (the unchanged vulnerable code)."""

    provider = "identity"

    def generate(self, messages, max_tokens, temperature=0.0, response_prefix="",
                 stop_on_json_close=False, context=None) -> GenerationResult:
        answer = (context or {}).get("identity_answer", "")
        return GenerationResult(text=answer, prompt_tokens=0, completion_tokens=0)


# --------------------------------------------------------------------------- #
# Local Hugging Face models
# --------------------------------------------------------------------------- #

class HFLocalClient(LLMClient):
    """Local transformers model. Spec keys: model, device, torch_dtype, load_in_4bit."""

    provider = "hf_local"
    supports_prefill = True

    def __init__(self, spec: Dict[str, Any], model: Any = None, tokenizer: Any = None) -> None:
        super().__init__(spec)
        self._model = model
        self._tokenizer = tokenizer
        self._loader = None

    def _ensure_loaded(self) -> None:
        if self._model is not None and self._tokenizer is not None:
            return
        if self.spec.get("load_in_4bit"):
            self._load_4bit()
            return
        from pipeline.model_loader import ModelConfig, ModelLoader

        cfg = ModelConfig(
            model_name_or_path=self.model,
            device=self.spec.get("device", "auto"),
            torch_dtype=self.spec.get("torch_dtype", "float16"),
        )
        self._loader = ModelLoader(cfg)
        self._model, self._tokenizer = self._loader.load()

    def _load_4bit(self) -> None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        except ImportError as err:  # pragma: no cover - environment specific
            raise LLMClientError(
                "4-bit loading needs transformers and bitsandbytes: pip install bitsandbytes"
            ) from err
        quant = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )
        logger.info("Loading '%s' in 4-bit (nf4)...", self.model)
        self._tokenizer = AutoTokenizer.from_pretrained(self.model)
        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token
        self._model = AutoModelForCausalLM.from_pretrained(
            self.model, quantization_config=quant, device_map="auto"
        )
        self._model.eval()

    def count_tokens(self, text: str) -> int:
        if self._tokenizer is not None:
            try:
                return len(self._tokenizer.encode(text, add_special_tokens=False))
            except Exception:
                pass
        return super().count_tokens(text)

    def _format(self, messages: List[Message]) -> str:
        try:
            return self._tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        except Exception:
            parts = [f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>" for m in messages]
            parts.append("<|im_start|>assistant\n")
            return "\n".join(parts)

    def generate(self, messages, max_tokens, temperature=0.0, response_prefix="",
                 stop_on_json_close=False, context=None) -> GenerationResult:
        import torch

        self._ensure_loaded()
        prompt = self._format(messages) + (response_prefix or "")
        start = time.perf_counter()
        try:
            inputs = self._tokenizer(prompt, return_tensors="pt")
            device = getattr(self._model, "device", None)
            if device is not None:
                inputs = {k: v.to(device) for k, v in inputs.items()}
            input_len = inputs["input_ids"].shape[1]
            max_ctx = self.spec.get("max_context_tokens")
            if max_ctx and input_len + max_tokens > max_ctx:
                max_tokens = max(64, max_ctx - input_len)

            gen_kwargs: Dict[str, Any] = {
                "max_new_tokens": max_tokens,
                "pad_token_id": self._tokenizer.pad_token_id or self._tokenizer.eos_token_id,
                "eos_token_id": self._tokenizer.eos_token_id,
                "do_sample": temperature > 0.0,
            }
            if temperature > 0.0:
                gen_kwargs["temperature"] = temperature
                gen_kwargs["top_p"] = self.spec.get("top_p", 0.95)
            if stop_on_json_close:
                from pipeline.inference import _build_json_stopping_criteria

                crit = _build_json_stopping_criteria(self._tokenizer, input_len, response_prefix)
                if crit is not None:
                    gen_kwargs["stopping_criteria"] = crit

            with torch.no_grad():
                out = self._model.generate(**inputs, **gen_kwargs)
            new_tokens = out[0][input_len:]
            text = self._tokenizer.decode(new_tokens, skip_special_tokens=True)
            n_new = len(new_tokens)
            return GenerationResult(
                text=(response_prefix or "") + text,
                prompt_tokens=int(input_len),
                completion_tokens=int(n_new),
                latency_seconds=round(time.perf_counter() - start, 3),
                finish_reason="length" if n_new >= max_tokens else "stop",
            )
        except Exception as err:
            if "out of memory" in str(err).lower():
                import gc

                gc.collect()
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            return GenerationResult(
                text="", latency_seconds=round(time.perf_counter() - start, 3),
                finish_reason="error", error=f"{type(err).__name__}: {err}",
            )

    def close(self) -> None:
        if self._loader is not None:
            self._loader.cleanup()
        self._model = None
        self._tokenizer = None
        try:
            import gc

            import torch

            gc.collect()
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except ImportError:  # pragma: no cover
            pass


# --------------------------------------------------------------------------- #
# Hosted APIs
# --------------------------------------------------------------------------- #

HttpPost = Callable[[str, Dict[str, str], Dict[str, Any], float], Dict[str, Any]]


def _default_http_post(url: str, headers: Dict[str, str], body: Dict[str, Any],
                       timeout: float) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class _HTTPClient(LLMClient):
    default_key_env = ""
    retry_statuses = (408, 409, 425, 429, 500, 502, 503, 504, 529)

    def __init__(self, spec: Dict[str, Any], http_post: Optional[HttpPost] = None) -> None:
        super().__init__(spec)
        self._post = http_post or _default_http_post
        self.timeout = float(spec.get("timeout_seconds", 180))
        self.max_retries = int(spec.get("max_retries", 5))
        key_env = spec.get("api_key_env", self.default_key_env)
        self.api_key = os.environ.get(key_env, "") if key_env else ""
        if key_env and not self.api_key and spec.get("require_api_key", True):
            raise LLMClientError(
                f"Model '{self.name}': environment variable {key_env} is not set."
            )

    def _request(self, url: str, headers: Dict[str, str], body: Dict[str, Any]) -> Dict[str, Any]:
        delay = 2.0
        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                return self._post(url, headers, body, self.timeout)
            except urllib.error.HTTPError as err:
                detail = ""
                try:
                    detail = err.read().decode("utf-8", "replace")[:500]
                except Exception:
                    pass
                last_err = LLMClientError(f"HTTP {err.code}: {detail}")
                if err.code not in self.retry_statuses:
                    raise last_err
            except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
                last_err = err
            if attempt < self.max_retries:
                logger.warning("%s: request failed (%s); retrying in %.0fs", self.name, last_err, delay)
                time.sleep(delay)
                delay = min(delay * 2, 60)
        raise LLMClientError(f"Request failed after retries: {last_err}")

    def generate(self, messages, max_tokens, temperature=0.0, response_prefix="",
                 stop_on_json_close=False, context=None) -> GenerationResult:
        start = time.perf_counter()
        try:
            result = self._generate(messages, max_tokens, temperature)
        except Exception as err:
            return GenerationResult(
                text="", latency_seconds=round(time.perf_counter() - start, 3),
                finish_reason="error", error=f"{type(err).__name__}: {err}",
            )
        result.latency_seconds = round(time.perf_counter() - start, 3)
        return result

    def _generate(self, messages, max_tokens, temperature) -> GenerationResult:
        raise NotImplementedError


class OpenAICompatibleClient(_HTTPClient):
    """OpenAI Chat Completions format. Works for OpenAI, Ollama, vLLM, LM Studio."""

    provider = "openai_compatible"
    default_key_env = ""

    def __init__(self, spec: Dict[str, Any], http_post: Optional[HttpPost] = None) -> None:
        super().__init__(spec, http_post)
        self.base_url = spec.get("base_url", "http://localhost:11434/v1").rstrip("/")

    def _generate(self, messages, max_tokens, temperature) -> GenerationResult:
        body: Dict[str, Any] = {"model": self.model, "messages": messages}
        body[self.spec.get("max_tokens_field", "max_tokens")] = max_tokens
        if self.spec.get("send_temperature", True):
            body["temperature"] = temperature
        body.update(self.spec.get("extra_body", {}))
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        data = self._request(f"{self.base_url}/chat/completions", headers, body)
        choice = (data.get("choices") or [{}])[0]
        usage = data.get("usage") or {}
        reason = choice.get("finish_reason") or "stop"
        return GenerationResult(
            text=(choice.get("message") or {}).get("content") or "",
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            finish_reason="length" if reason == "length" else "stop",
            raw={"finish_reason": reason, "model": data.get("model")},
        )


class OpenAIClient(OpenAICompatibleClient):
    provider = "openai"
    default_key_env = "OPENAI_API_KEY"

    def __init__(self, spec: Dict[str, Any], http_post: Optional[HttpPost] = None) -> None:
        spec = {"base_url": "https://api.openai.com/v1", "max_tokens_field": "max_completion_tokens", **spec}
        super().__init__(spec, http_post)


class AnthropicClient(_HTTPClient):
    provider = "anthropic"
    default_key_env = "ANTHROPIC_API_KEY"

    def _generate(self, messages, max_tokens, temperature) -> GenerationResult:
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        convo = [m for m in messages if m["role"] != "system"]
        body: Dict[str, Any] = {"model": self.model, "max_tokens": max_tokens, "messages": convo}
        if system:
            body["system"] = system
        if self.spec.get("send_temperature", True):
            body["temperature"] = temperature
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        base = self.spec.get("base_url", "https://api.anthropic.com/v1").rstrip("/")
        data = self._request(f"{base}/messages", headers, body)
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        usage = data.get("usage") or {}
        reason = data.get("stop_reason") or "end_turn"
        return GenerationResult(
            text=text,
            prompt_tokens=usage.get("input_tokens"),
            completion_tokens=usage.get("output_tokens"),
            finish_reason="length" if reason == "max_tokens" else "stop",
            raw={"stop_reason": reason, "model": data.get("model")},
        )


class GeminiClient(_HTTPClient):
    provider = "gemini"
    default_key_env = "GEMINI_API_KEY"

    def _generate(self, messages, max_tokens, temperature) -> GenerationResult:
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        contents = [
            {"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
            for m in messages if m["role"] != "system"
        ]
        gen_cfg: Dict[str, Any] = {"maxOutputTokens": max_tokens}
        if self.spec.get("send_temperature", True):
            gen_cfg["temperature"] = temperature
        body: Dict[str, Any] = {"contents": contents, "generationConfig": gen_cfg}
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        base = self.spec.get("base_url", "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
        data = self._request(
            f"{base}/models/{self.model}:generateContent", {"x-goog-api-key": self.api_key}, body
        )
        cand = (data.get("candidates") or [{}])[0]
        text = "".join(p.get("text", "") for p in (cand.get("content") or {}).get("parts", []))
        usage = data.get("usageMetadata") or {}
        reason = cand.get("finishReason") or "STOP"
        return GenerationResult(
            text=text,
            prompt_tokens=usage.get("promptTokenCount"),
            completion_tokens=usage.get("candidatesTokenCount"),
            finish_reason="length" if reason == "MAX_TOKENS" else "stop",
            raw={"finish_reason": reason},
        )


PROVIDERS = {
    "hf_local": HFLocalClient,
    "openai": OpenAIClient,
    "openai_compatible": OpenAICompatibleClient,
    "anthropic": AnthropicClient,
    "gemini": GeminiClient,
    "oracle": OracleClient,
    "identity": IdentityClient,
}


def build_client(spec: Dict[str, Any], **kwargs: Any) -> LLMClient:
    provider = spec.get("provider")
    if provider not in PROVIDERS:
        raise LLMClientError(
            f"Unknown provider '{provider}' for model '{spec.get('name')}'. "
            f"Choose one of: {', '.join(sorted(PROVIDERS))}"
        )
    return PROVIDERS[provider](spec, **kwargs)
