# VajraLink - SAST/DAST correlation platform.
# Builds an image with every scanning engine it uses already inside it: Semgrep, Bandit, Playwright +
# Chromium, and (best-effort, optional) the katana crawler. `docker compose up --build` is the whole setup.
FROM python:3.12-slim

# System packages:
#   git    - repo cloning (Step 1: point VajraLink at any GitHub URL)
#   curl, unzip, ca-certificates - fetching the optional katana release binary
# Playwright's own OS dependencies are installed separately below via `playwright install --with-deps`.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Python dependencies first (own layer, cached across code-only changes) ---
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Sanity-check that Semgrep and Bandit really installed and run inside this image, not just "pip said OK".
RUN semgrep --version && bandit --version

# --- Playwright's Chromium + its OS-level dependencies (apt packages playwright itself requires) ---
RUN python -m playwright install --with-deps chromium

# --- Optional: katana crawler (vajra/dast/katana_crawl.py auto-detects it; everything else works
#     without it, so a failure here must never fail the image build) ---
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    case "$ARCH" in \
        amd64) KARCH=amd64 ;; \
        arm64) KARCH=arm64 ;; \
        *) KARCH=amd64 ;; \
    esac; \
    TAG="$(curl -fsSL https://api.github.com/repos/projectdiscovery/katana/releases/latest \
        | grep -m1 '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')" || true; \
    if [ -n "$TAG" ]; then \
        curl -fsSL -o /tmp/katana.zip \
            "https://github.com/projectdiscovery/katana/releases/download/v${TAG}/katana_${TAG}_linux_${KARCH}.zip" \
        && unzip -oq /tmp/katana.zip -d /usr/local/bin katana \
        && chmod +x /usr/local/bin/katana \
        && rm -f /tmp/katana.zip \
        && katana -version; \
    else \
        echo "katana release lookup failed at build time - continuing without it (optional, auto-detected)"; \
    fi

# --- Application code ---
COPY . .

RUN mkdir -p /app/screenshots /app/data

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "vajra.api:app", "--host", "0.0.0.0", "--port", "8000"]
