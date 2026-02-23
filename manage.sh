#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  BotTGDomains — unified project manager (Linux / macOS)
#  Usage:  ./manage.sh <command> [args]
# ============================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

ENV_FILE=".env"
ENV_EXAMPLE=".env.example"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[OK]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[!!]${NC}  $*"; }
err()   { echo -e "${RED}[ERR]${NC} $*" >&2; }
step()  { echo -e "${CYAN}==> $*${NC}"; }

# ---------- helpers ----------

_detect_compose() {
    if docker compose version &>/dev/null; then
        echo "docker compose"
    elif command -v docker-compose &>/dev/null; then
        echo "docker-compose"
    else
        err "Docker Compose not found"; exit 1
    fi
}

_require_docker() {
    command -v docker &>/dev/null || { err "Docker is not installed"; exit 1; }
    _detect_compose >/dev/null
    info "Docker & Compose detected"
}

_ensure_dirs() {
    mkdir -p data
    mkdir -p wg
}

_ensure_env() {
    if [ ! -f "$ENV_FILE" ]; then
        if [ -f "$ENV_EXAMPLE" ]; then
            cp "$ENV_EXAMPLE" "$ENV_FILE"
            warn ".env created from .env.example — edit it now!"
            echo "    Required:  TG_TOKEN  and  ADMIN_ID"
            read -rp "    Press Enter after editing $ENV_FILE ..."
        else
            err ".env.example not found"; exit 1
        fi
    fi
}

_validate_env() {
    local token admin
    token=$(grep -E '^TG_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    admin=$(grep -E '^ADMIN_ID=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')

    if [ -z "$token" ] || [ "$token" = "your_telegram_bot_token_here" ] || [ "$token" = "ID" ]; then
        err "TG_TOKEN is not set in $ENV_FILE"; exit 1
    fi
    if [ -z "$admin" ] || [ "$admin" = "your_telegram_user_id_here" ]; then
        err "ADMIN_ID is not set in $ENV_FILE"; exit 1
    fi
    info "Config validated (TG_TOKEN and ADMIN_ID are set)"
}

_find_image() {
    local pattern="$1"
    docker images --format "{{.Repository}}:{{.Tag}}" | grep -iE "$pattern" | grep -v '<none>' | head -1
}

DC=""  # populated lazily
_dc() { [ -z "$DC" ] && DC=$(_detect_compose); $DC "$@"; }

# ---------- commands ----------

cmd_start() {
    step "Starting BotTGDomains"
    _require_docker
    _ensure_dirs
    _ensure_env
    _validate_env

    step "Stopping existing containers (if any)"
    _dc down 2>/dev/null || true

    step "Building & starting services"
    _dc up -d --build

    echo ""
    step "Waiting for services to become healthy (10 s)"
    sleep 10

    echo ""
    _dc ps
    echo ""
    info "Bot is running!  Send /start to the bot in Telegram."
    echo ""
    echo "  Logs:     $(_detect_compose) logs -f tgscanner"
    echo "  Stop:     ./manage.sh stop"
    echo "  Restart:  ./manage.sh restart"
    echo "  Status:   ./manage.sh status"
}

cmd_stop() {
    step "Stopping services"
    _require_docker
    _dc down
    info "All services stopped"
}

cmd_restart() {
    local svc="${1:-}"
    _require_docker
    if [ -n "$svc" ]; then
        step "Restarting service: $svc"
        _dc restart "$svc"
    else
        step "Restarting all services"
        _dc down 2>/dev/null || true
        _dc up -d --build
        sleep 5
        _dc ps
    fi
    info "Restart complete"
}

cmd_build() {
    step "Building Docker images"
    _require_docker
    local flag=""
    if [ "${1:-}" = "--no-cache" ]; then flag="--no-cache"; fi
    _dc build $flag
    info "Build complete"
}

cmd_logs() {
    _require_docker
    local svc="${1:-tgscanner}"
    _dc logs -f "$svc"
}

cmd_status() {
    _require_docker
    _dc ps
}

cmd_check() {
    step "Configuration check"
    _require_docker

    echo ""
    if [ -f "$ENV_FILE" ]; then
        info ".env file exists"
        _validate_env
    else
        warn ".env file is missing (run ./manage.sh start to create)"
    fi

    echo ""
    if [ -f "wg/TGBOT.conf" ]; then
        local lines
        lines=$(wc -l < "wg/TGBOT.conf")
        if [ "$lines" -gt 3 ]; then
            info "WireGuard config found ($lines lines)"
        else
            warn "WireGuard config looks like a placeholder ($lines lines)"
        fi
    else
        warn "WireGuard config not found (wg/TGBOT.conf)"
    fi

    echo ""
    if [ -f "docker-compose.yml" ]; then
        info "docker-compose.yml present"
    else
        err "docker-compose.yml missing!"
    fi

    echo ""
    info "Check complete"
}

cmd_export() {
    step "Building offline deployment package"
    _require_docker

    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local EXPORT_DIR="$PROJECT_ROOT/export"
    local ARCHIVE="bottgdomains-offline-${ts}.tar.gz"

    # 1 — ensure wg config placeholder
    _ensure_dirs
    if [ ! -f "wg/TGBOT.conf" ]; then
        echo "# Placeholder — replace with real config before use" > wg/TGBOT.conf
        warn "Created placeholder wg/TGBOT.conf"
    fi

    # 2 — build
    step "Building images (no-cache)"
    _dc build --no-cache

    # 3 — prepare export dir
    rm -rf "$EXPORT_DIR"
    mkdir -p "$EXPORT_DIR/images" "$EXPORT_DIR/project"

    # 4 — save images
    step "Exporting Docker images"

    local PROJECT_NAME
    PROJECT_NAME=$(basename "$PROJECT_ROOT" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
    [ ${#PROJECT_NAME} -lt 3 ] && PROJECT_NAME="bottgdomains"

    # gostsslcheck
    local gost_img
    gost_img=$(_find_image "^${PROJECT_NAME}[-_]?gostsslcheck") || true
    [ -z "$gost_img" ] && gost_img=$(_find_image "gostsslcheck") || true
    [ -z "$gost_img" ] && { err "gostsslcheck image not found"; exit 1; }
    echo "  gostsslcheck -> $gost_img"
    docker save "$gost_img" -o "$EXPORT_DIR/images/gostsslcheck.tar"

    # tgscanner
    local tg_img
    tg_img=$(_find_image "^${PROJECT_NAME}[-_]?tgscanner") || true
    [ -z "$tg_img" ] && tg_img=$(_find_image "tgscanner") || true
    [ -z "$tg_img" ] && { err "tgscanner image not found"; exit 1; }
    echo "  tgscanner    -> $tg_img"
    docker save "$tg_img" -o "$EXPORT_DIR/images/tgscanner.tar"

    # wireguard
    docker pull masipcat/wireguard-go:latest 2>/dev/null || true
    if docker image inspect masipcat/wireguard-go:latest &>/dev/null; then
        echo "  wireguard    -> masipcat/wireguard-go:latest"
        docker save masipcat/wireguard-go:latest -o "$EXPORT_DIR/images/wireguard.tar"
    else
        warn "masipcat/wireguard-go:latest not available locally"
    fi

    # 5 — copy project files
    step "Copying project files"
    cp docker-compose.yml "$EXPORT_DIR/project/"
    [ -f .env.example ] && cp .env.example "$EXPORT_DIR/project/"
    cp -r bot "$EXPORT_DIR/project/"
    cp -r gost "$EXPORT_DIR/project/"
    [ -d wg ] && cp -r wg "$EXPORT_DIR/project/"
    [ -f scripts/deploy.sh ] && cp scripts/deploy.sh "$EXPORT_DIR/project/" && chmod +x "$EXPORT_DIR/project/deploy.sh"
    [ -f manage.sh ] && cp manage.sh "$EXPORT_DIR/project/" && chmod +x "$EXPORT_DIR/project/manage.sh"
    for doc in README.md CHANGELOG.md DEPLOYMENT_OFFLINE.md QUICKSTART.md; do
        [ -f "$doc" ] && cp "$doc" "$EXPORT_DIR/project/"
    done

    # clean
    rm -rf "$EXPORT_DIR/project/bot/data" 2>/dev/null || true
    find "$EXPORT_DIR/project" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    find "$EXPORT_DIR/project" -name "*.pyc" -delete 2>/dev/null || true
    find "$EXPORT_DIR/project" -name ".pytest_cache" -type d -exec rm -rf {} + 2>/dev/null || true

    # 6 — archive
    step "Creating archive"
    (cd "$EXPORT_DIR" && tar -czf "$PROJECT_ROOT/$ARCHIVE" images/ project/)
    local size
    size=$(du -h "$PROJECT_ROOT/$ARCHIVE" | cut -f1)

    # 7 — checksum
    if command -v sha256sum &>/dev/null; then
        sha256sum "$PROJECT_ROOT/$ARCHIVE" > "$PROJECT_ROOT/$ARCHIVE.sha256"
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$PROJECT_ROOT/$ARCHIVE" > "$PROJECT_ROOT/$ARCHIVE.sha256"
    fi

    echo ""
    info "Offline package ready:"
    echo "  Archive:  $ARCHIVE  ($size)"
    [ -f "$PROJECT_ROOT/$ARCHIVE.sha256" ] && echo "  Checksum: $ARCHIVE.sha256"
    echo ""
    echo "  Transfer the archive to the target VM, then run:"
    echo "    tar -xzf $ARCHIVE"
    echo "    cd project && ./manage.sh deploy"
}

cmd_deploy() {
    step "Offline deployment"
    _require_docker

    local IMAGES_DIR="$PROJECT_ROOT/../images"

    if [ -d "$IMAGES_DIR" ]; then
        step "Loading Docker images from $IMAGES_DIR"
        for tar_file in "$IMAGES_DIR"/*.tar; do
            [ -f "$tar_file" ] || continue
            echo "  Loading $(basename "$tar_file") ..."
            docker load -i "$tar_file"
        done

        # tag gostsslcheck replicas
        local gost_img
        gost_img=$(_find_image "gostsslcheck") || true
        if [ -n "$gost_img" ]; then
            for i in 1 2 3; do
                docker tag "$gost_img" "bottgdomains-gostsslcheck${i}:latest" 2>/dev/null || true
            done
            info "Tagged gostsslcheck replicas"
        fi

        local tg_img
        tg_img=$(_find_image "tgscanner") || true
        [ -n "$tg_img" ] && docker tag "$tg_img" "bottgdomains-tgscanner:latest" 2>/dev/null || true

        # override
        cat > docker-compose.override.yml << 'OVERRIDE'
services:
  gostsslcheck1:
    image: bottgdomains-gostsslcheck1:latest
  gostsslcheck2:
    image: bottgdomains-gostsslcheck2:latest
  gostsslcheck3:
    image: bottgdomains-gostsslcheck3:latest
  tgscanner:
    image: bottgdomains-tgscanner:latest
  wireguard:
    image: masipcat/wireguard-go:latest
OVERRIDE
        info "docker-compose.override.yml created"
    else
        warn "No images/ directory found — assuming images already loaded"
    fi

    _ensure_dirs
    _ensure_env
    _validate_env

    step "Starting services (no-build, no-pull)"
    _dc down 2>/dev/null || true
    _dc up -d --no-build --pull never

    sleep 5
    _dc ps
    echo ""
    info "Deployment complete"
}

cmd_help() {
    cat <<USAGE

  BotTGDomains Manager
  ====================

  Usage:  ./manage.sh <command> [args]

  Commands:
    start           Build & launch all services (quickstart)
    stop            Stop all services
    restart [svc]   Restart all or a specific service
    build [--no-cache]  Build Docker images
    logs [svc]      Follow logs (default: tgscanner)
    status          Show service status
    check           Validate configuration
    export          Build offline deployment package
    deploy          Load images & start (offline mode)
    help            Show this message

USAGE
}

# ---------- dispatch ----------

case "${1:-help}" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    restart) shift; cmd_restart "$@" ;;
    build)   shift; cmd_build "$@" ;;
    logs)    shift; cmd_logs "$@" ;;
    status)  cmd_status ;;
    check)   cmd_check ;;
    export)  cmd_export ;;
    deploy)  cmd_deploy ;;
    help|--help|-h) cmd_help ;;
    *)       err "Unknown command: $1"; cmd_help; exit 1 ;;
esac
