#!/usr/bin/env bash
set -euo pipefail

UI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$UI_DIR/backend"
FRONTEND_DIR="$UI_DIR/frontend"
CPP_DIR="$BACKEND_DIR/cpp_bridge"

DEV_MODE=0
REBUILD=0
for arg in "$@"; do
  case "$arg" in
    --dev) DEV_MODE=1 ;;
    --rebuild) REBUILD=1 ;;
    -h|--help)
      echo "Usage: ./ui/start.sh [--dev] [--rebuild]"
      echo "  default    Build missing artifacts and serve UI + API on http://127.0.0.1:8000"
      echo "  --dev      Run FastAPI on :8000 and Vite dev server on :5173 with hot reload"
      echo "  --rebuild  Force rebuild of C++ bridge binaries and frontend production bundle"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

echo "[1/3] Checking C++ bridge binaries..."
if [[ "$REBUILD" -eq 1 ]] || [[ ! -x "$CPP_DIR/bin/aes256_cli" ]] || [[ ! -x "$CPP_DIR/bin/rsa_cli" ]] || [[ ! -x "$CPP_DIR/bin/ecc_sha_cli" ]] || [[ ! -x "$CPP_DIR/bin/q2_runner" ]]; then
  make -C "$CPP_DIR"
fi

echo "[2/3] Checking Python backend environment..."
if [[ ! -x "$BACKEND_DIR/.venv/bin/python" ]]; then
  python3 -m venv "$BACKEND_DIR/.venv"
  "$BACKEND_DIR/.venv/bin/pip" install --upgrade pip
  "$BACKEND_DIR/.venv/bin/pip" install -r "$BACKEND_DIR/requirements.txt"
fi

if [[ "$DEV_MODE" -eq 1 ]]; then
  if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
    echo "[3/3] Installing frontend dependencies..."
    (cd "$FRONTEND_DIR" && npm install)
  fi
  echo "Starting FastAPI (:8000) and Vite dev server (:5173)..."
  (cd "$BACKEND_DIR" && "$BACKEND_DIR/.venv/bin/uvicorn" app:app --host 127.0.0.1 --port 8000 --reload) &
  BACK_PID=$!
  trap 'kill "$BACK_PID" 2>/dev/null || true' EXIT INT TERM
  cd "$FRONTEND_DIR"
  npm run dev -- --host 127.0.0.1 --port 5173
else
  echo "[3/3] Checking frontend production bundle..."
  if [[ "$REBUILD" -eq 1 ]] || [[ ! -f "$FRONTEND_DIR/dist/index.html" ]]; then
    if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
      (cd "$FRONTEND_DIR" && npm install)
    fi
    (cd "$FRONTEND_DIR" && npm run build)
  fi
  echo "Serving Cryptography & Quantum Attack Lab at http://127.0.0.1:8000"
  cd "$BACKEND_DIR"
  exec "$BACKEND_DIR/.venv/bin/uvicorn" app:app --host 127.0.0.1 --port 8000
fi
