#!/usr/bin/env bash
# Checks everything the multi-model evaluation pipeline needs, without running any model.
#
#   bash scripts/check_eval_environment.sh                 # quick checks
#   bash scripts/check_eval_environment.sh CVE-2017-6832   # + sandbox smoke test for one case
#
# The smoke test starts the Vul4C container, checks out the case, compiles it and runs its
# proof-of-concept exploit. The exploit runs only inside the container.

IMAGE="${VUL4C_IMAGE:-vul4c/vul4c:4.0}"
CVE="$1"
ok()   { echo "  [OK]   $*"; }
warn() { echo "  [WARN] $*"; }
fail() { echo "  [FAIL] $*"; }

echo "== Python packages"
python3 - <<'EOF'
import importlib
for mod, need in [("torch", "local models"), ("transformers", "local models"),
                  ("bitsandbytes", "4-bit 7B models (optional)")]:
    try:
        m = importlib.import_module(mod)
        print(f"  [OK]   {mod} {getattr(m, '__version__', '')}")
    except Exception:
        print(f"  [WARN] {mod} not importable ({need})")
try:
    import torch
    print("  [OK]   CUDA available" if torch.cuda.is_available() else "  [WARN] CUDA not available (local models will be slow)")
except Exception:
    pass
EOF

echo "== Static analysis tools"
command -v cppcheck   >/dev/null && ok "cppcheck $(cppcheck --version 2>/dev/null)"   || warn "cppcheck missing: sudo apt install cppcheck"
command -v flawfinder >/dev/null && ok "flawfinder $(flawfinder --version 2>/dev/null)" || warn "flawfinder missing: pip install flawfinder"

echo "== API keys (only needed for enabled API models)"
for k in ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY; do
  [ -n "${!k}" ] && ok "$k is set" || echo "  [--]   $k not set"
done

echo "== Docker"
if ! command -v docker >/dev/null; then
  fail "docker not found. Install Docker Desktop (WSL integration) or docker.io, then re-run."
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  fail "docker daemon not reachable (is Docker Desktop running / is your user in the docker group?)"
  exit 1
fi
ok "docker daemon reachable"
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  ok "image $IMAGE present"
else
  echo "  ...  pulling $IMAGE (large, one-time)"
  docker pull "$IMAGE" && ok "pulled $IMAGE" || { fail "could not pull $IMAGE"; exit 1; }
fi
if docker run --rm "$IMAGE" bash -lc "command -v vul4c" >/dev/null 2>&1; then
  ok "vul4c CLI available inside the image"
else
  warn "vul4c CLI not found in the image. Mount the SoK repo and install it via config 'sandbox':"
  echo '         "mounts": ["/path/to/SoK-main/SoK-main:/sok"],'
  echo '         "setup_commands": ["cd /sok && python3 setup.py install"]'
fi

if [ -n "$CVE" ]; then
  echo "== Sandbox smoke test for $CVE (vulnerable version; exploit should crash)"
  NAME="vul4c_check_$$"
  docker run -d --name "$NAME" --cpus 2 --memory 6g "$IMAGE" sleep infinity >/dev/null
  trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT
  docker exec "$NAME" bash -lc "vul4c checkout -i $CVE -d /tmp/check" | tail -5 || fail "checkout failed"
  docker network disconnect bridge "$NAME" >/dev/null 2>&1
  docker exec "$NAME" bash -lc "vul4c compile -d /tmp/check" | tail -5 || fail "compile failed"
  OUT=$(docker exec "$NAME" bash -lc "timeout 300 vul4c reproduce -d /tmp/check" 2>&1)
  echo "$OUT" | tail -15
  if echo "$OUT" | grep -qE "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|Segmentation fault|SEGV"; then
    ok "exploit reproduces the vulnerability (expected)"
  else
    warn "no sanitizer crash detected; check the output above and the crash_patterns in the config"
  fi
fi
echo "Done."
