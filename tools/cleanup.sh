#!/bin/bash
# ============================================================================
# Armada - Bot Persistence Cleanup
# ============================================================================
# Removes ALL persistence artifacts created by the bot on the local machine.
# Handles both old (Makefile) and new (build.sh) binary naming conventions,
# plus all runtime persistence paths (systemd, cron, rc.local, hidden dirs).
#
# Run as root.
# ============================================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
skip() { echo -e "${YELLOW}[-]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root"
    exit 1
fi

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║${NC}   Armada Bot Persistence Cleanup                 ${RED}║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================================================
# All known persistence identifiers (current + legacy)
# ============================================================================

# Current config names (redis-themed)
CUR_SERVICE="redis-sentinel.service"
CUR_SERVICE_PATH="/etc/systemd/system/${CUR_SERVICE}"
CUR_HIDDEN_DIR="/var/lib/redis/.rdb_cache"
CUR_SCRIPT=".redis-aof-rewrite.sh"
CUR_BINARY=".redis-sentinel"
CUR_LOCK="/tmp/.redis-server.pid"
CUR_SPEED="/tmp/.dbus-session"
CUR_ENV="__SSHD_DAEMON"
FETCH_URL="176.65.148.112/init.sh"

# Legacy config names (httpd-themed — from older builds)
OLD_SERVICE="httpd-cache.service"
OLD_SERVICE_PATH="/etc/systemd/system/${OLD_SERVICE}"
OLD_HIDDEN_DIR="/var/lib/.httpd_cache"
OLD_SCRIPT=".httpd_check.sh"
OLD_BINARY=".httpd_worker"
OLD_LOCK="/tmp/.X11-unix/.X0-lock"

# All known cross-compiled binary names
# build.sh names (redis-themed)
BUILD_SH_NAMES="redis-daemon redis-proxyd redis-initd redis-credentiald redis-swarmd redis-composd redis-conteinerd redis-conteinerd-shim redis-runcd redis-buildxd redis-scoutd redis-sbomd redis-machined redis-scand"
# Makefile names (kernel-thread-themed)
MAKEFILE_NAMES="migration_0 migration_1 rcu_preempt kthreadd kintegrityd_be ksoftirqd kintegrityd writeback_0 writeback_1 writeback_2 cryptd irq_work rcu_sched"
# Camo names (redis-themed, used at runtime with random suffixes)
CAMO_PREFIXES="redis-server redis-sentinel redis-cli rdb-check aof-rewrite"

ALL_BIN_NAMES="${BUILD_SH_NAMES} ${MAKEFILE_NAMES}"

# ============================
# 1. Kill running bot processes
# ============================
info "Killing bot processes..."
KILLED=0

# Kill by exact binary name
for bname in ${ALL_BIN_NAMES} ${CUR_BINARY} ${OLD_BINARY}; do
    if pgrep -x "${bname}" > /dev/null 2>&1; then
        pkill -9 -x "${bname}" 2>/dev/null && ok "Killed ${bname}" && KILLED=$((KILLED+1))
    fi
done

# Kill dotfile variants (.migration_0, .redis-daemon, etc.)
for bname in ${ALL_BIN_NAMES}; do
    if pgrep -x ".${bname}" > /dev/null 2>&1; then
        pkill -9 -x ".${bname}" 2>/dev/null && ok "Killed .${bname}" && KILLED=$((KILLED+1))
    fi
done

# Kill by camo prefix pattern (redis-server-xxxx, redis-sentinel-yyyy, etc.)
for prefix in ${CAMO_PREFIXES}; do
    if pgrep -f "^${prefix}-" > /dev/null 2>&1; then
        pkill -9 -f "^${prefix}-" 2>/dev/null && ok "Killed ${prefix}-* processes" && KILLED=$((KILLED+1))
    fi
done

# Kill anything from known dirs
for dir in "${CUR_HIDDEN_DIR}" "${OLD_HIDDEN_DIR}" "/dev/shm"; do
    for bname in ${ALL_BIN_NAMES} ${CUR_BINARY} ${OLD_BINARY}; do
        if pgrep -f "${dir}/.*${bname}" > /dev/null 2>&1; then
            pkill -9 -f "${dir}/.*${bname}" 2>/dev/null && ok "Killed from ${dir}/${bname}" && KILLED=$((KILLED+1))
        fi
        if pgrep -f "${dir}/\\.${bname}" > /dev/null 2>&1; then
            pkill -9 -f "${dir}/\\.${bname}" 2>/dev/null && ok "Killed from ${dir}/.${bname}" && KILLED=$((KILLED+1))
        fi
    done
done

# Kill from Armada dirs
if pgrep -f "Armada/bins/" > /dev/null 2>&1; then
    pkill -9 -f "Armada/bins/" && ok "Killed processes from Armada/bins/" && KILLED=$((KILLED+1))
fi

[ $KILLED -eq 0 ] && skip "No running bot processes found"

# ============================
# 2. Remove systemd services
# ============================
info "Checking systemd services..."

for svc_name in "${CUR_SERVICE}" "${OLD_SERVICE}"; do
    svc_path="/etc/systemd/system/${svc_name}"
    if systemctl is-active --quiet "${svc_name}" 2>/dev/null; then
        systemctl stop "${svc_name}" 2>/dev/null && ok "Stopped ${svc_name}"
    fi
    if systemctl is-enabled --quiet "${svc_name}" 2>/dev/null; then
        systemctl disable "${svc_name}" 2>/dev/null && ok "Disabled ${svc_name}"
    fi
    if [ -f "${svc_path}" ]; then
        rm -f "${svc_path}" && ok "Removed ${svc_path}"
    fi
done

# Also search for any systemd unit mentioning known binaries
for bname in ${CUR_BINARY} ${OLD_BINARY}; do
    for f in /etc/systemd/system/*.service; do
        [ -f "$f" ] || continue
        if grep -q "${bname}" "$f" 2>/dev/null; then
            sn=$(basename "$f")
            systemctl stop "${sn}" 2>/dev/null
            systemctl disable "${sn}" 2>/dev/null
            rm -f "$f" && ok "Removed rogue service ${sn}"
        fi
    done
done

systemctl daemon-reload 2>/dev/null

# ============================
# 3. Remove hidden directories
# ============================
info "Checking hidden directories..."

for dir in "${CUR_HIDDEN_DIR}" "${OLD_HIDDEN_DIR}"; do
    if [ -d "${dir}" ]; then
        rm -rf "${dir}" && ok "Removed ${dir}"
    else
        skip "${dir} does not exist"
    fi
done

# Check /dev/shm for dotfile binaries
for bname in ${ALL_BIN_NAMES} ${CUR_BINARY} ${OLD_BINARY}; do
    if [ -f "/dev/shm/.${bname}" ]; then
        rm -f "/dev/shm/.${bname}" && ok "Removed /dev/shm/.${bname}"
    fi
done

# ============================
# 4. Clean cron jobs
# ============================
info "Cleaning crontab..."

CRON_BEFORE=$(crontab -l 2>/dev/null || true)
if [ -z "${CRON_BEFORE}" ]; then
    skip "No crontab entries"
else
    CRON_CLEANED="${CRON_BEFORE}"
    CRON_REMOVED=0

    # Build grep pattern for all known names
    ALL_CRON_PATTERNS="${CUR_SCRIPT} ${OLD_SCRIPT} ${CUR_BINARY} ${OLD_BINARY} ${CUR_HIDDEN_DIR} ${OLD_HIDDEN_DIR} ${FETCH_URL}"
    for bname in ${ALL_BIN_NAMES}; do
        ALL_CRON_PATTERNS="${ALL_CRON_PATTERNS} ${bname}"
    done
    for prefix in ${CAMO_PREFIXES}; do
        ALL_CRON_PATTERNS="${ALL_CRON_PATTERNS} ${prefix}"
    done

    for pattern in ${ALL_CRON_PATTERNS}; do
        if echo "${CRON_CLEANED}" | grep -q "${pattern}"; then
            CRON_CLEANED=$(echo "${CRON_CLEANED}" | grep -v "${pattern}")
            ok "Removed cron entries matching '${pattern}'"
            CRON_REMOVED=$((CRON_REMOVED+1))
        fi
    done

    if [ $CRON_REMOVED -gt 0 ]; then
        # Remove blank lines and apply
        CRON_CLEANED=$(echo "${CRON_CLEANED}" | sed '/^$/d')
        if [ -n "${CRON_CLEANED}" ]; then
            echo "${CRON_CLEANED}" | crontab - 2>/dev/null
        else
            crontab -r 2>/dev/null || true
        fi
        ok "Crontab cleaned (${CRON_REMOVED} patterns removed)"
    else
        skip "No bot cron entries found"
    fi
fi

# ============================
# 5. Clean rc.local
# ============================
info "Checking /etc/rc.local..."

RC_LOCAL="/etc/rc.local"
if [ -f "${RC_LOCAL}" ]; then
    RC_CLEANED=0
    for pattern in ${CUR_BINARY} ${OLD_BINARY} ${CUR_HIDDEN_DIR} ${OLD_HIDDEN_DIR} ${CUR_SCRIPT} ${OLD_SCRIPT} ${FETCH_URL}; do
        if grep -q "${pattern}" "${RC_LOCAL}" 2>/dev/null; then
            escaped=$(echo "${pattern}" | sed 's/[\/&]/\\&/g')
            sed -i "/${escaped}/d" "${RC_LOCAL}"
            ok "Removed rc.local entries matching '${pattern}'"
            RC_CLEANED=$((RC_CLEANED+1))
        fi
    done
    for bname in ${ALL_BIN_NAMES}; do
        if grep -q "${bname}" "${RC_LOCAL}" 2>/dev/null; then
            sed -i "/${bname}/d" "${RC_LOCAL}"
            ok "Removed rc.local entry for ${bname}"
            RC_CLEANED=$((RC_CLEANED+1))
        fi
    done
    [ $RC_CLEANED -eq 0 ] && skip "No bot entries in ${RC_LOCAL}"
else
    skip "${RC_LOCAL} does not exist"
fi

# ============================
# 6. Remove temp/lock files
# ============================
info "Cleaning temp files..."

for f in "${CUR_LOCK}" "${OLD_LOCK}" "${CUR_SPEED}"; do
    if [ -f "${f}" ]; then
        rm -f "${f}" && ok "Removed ${f}"
    else
        skip "${f} does not exist"
    fi
done

# ============================
# 7. Kill single-instance lock port
# ============================
info "Checking single-instance lock port (42780)..."

LOCK_PID=$(fuser 42780/tcp 2>/dev/null | tr -d ' ')
if [ -n "${LOCK_PID}" ]; then
    kill -9 ${LOCK_PID} 2>/dev/null && ok "Killed lock holder PID ${LOCK_PID} on port 42780"
else
    skip "Port 42780 not in use"
fi

# ============================
# 8. Remove stray binaries from common paths
# ============================
info "Checking for stray binaries..."

for bname in ${ALL_BIN_NAMES} ${CUR_BINARY} ${OLD_BINARY}; do
    for dir in /root /tmp /var/tmp /dev/shm /usr/bin /usr/local/bin; do
        if [ -f "${dir}/${bname}" ]; then
            rm -f "${dir}/${bname}" && ok "Removed ${dir}/${bname}"
        fi
        if [ -f "${dir}/.${bname}" ]; then
            rm -f "${dir}/.${bname}" && ok "Removed ${dir}/.${bname}"
        fi
    done
done

# ============================
# Done
# ============================
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Cleanup complete.${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo ""

# Verify
REMAINING_CRON=$(crontab -l 2>/dev/null || true)
if [ -n "${REMAINING_CRON}" ]; then
    info "Remaining crontab entries:"
    echo "${REMAINING_CRON}" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        echo "    ${line}"
    done
else
    info "Crontab is clean"
fi
echo ""
