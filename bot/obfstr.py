#!/usr/bin/env python3
"""
obfstr.py -- Build-time XOR string obfuscator for bot source files.

Scans C source files for string literals, XOR-encrypts them with a fresh
random key, and writes obfuscated copies to obf/.  Also writes the key to
headers/strenc.h so the runtime _S() macro can decrypt on the stack.

Usage: python3 obfstr.py file1.c [file2.c ...]

Skipped entirely:  config.c, crypto.c
Skipped strings:   file-scope (brace depth 0), preprocessor lines (#define /
                   #include / #pragma), static declarations (direct or nested
                   inside static initializers), char array initializers,
                   sizeof() args, empty strings.
"""

import re
import sys
import os
import random

SKIP_FILES = {'config.c', 'crypto.c'}
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


# ---------------------------------------------------------------------------
# C string literal -> bytes
# ---------------------------------------------------------------------------

def parse_c_string(content):
    """Convert the inner content of a C string literal (no outer quotes) to bytes."""
    result = []
    i = 0
    while i < len(content):
        if content[i] != '\\':
            result.append(ord(content[i]) & 0xFF)
            i += 1
            continue
        i += 1
        if i >= len(content):
            break
        esc = content[i]
        if   esc == 'n':  result.append(0x0A)
        elif esc == 't':  result.append(0x09)
        elif esc == 'r':  result.append(0x0D)
        elif esc == '0':  result.append(0x00)
        elif esc == '\\': result.append(0x5C)
        elif esc == '"':  result.append(0x22)
        elif esc == "'":  result.append(0x27)
        elif esc == 'a':  result.append(0x07)
        elif esc == 'b':  result.append(0x08)
        elif esc == 'f':  result.append(0x0C)
        elif esc == 'v':  result.append(0x0B)
        elif esc == 'x':
            i += 1
            hex_s = ''
            while i < len(content) and content[i] in '0123456789abcdefABCDEF' and len(hex_s) < 2:
                hex_s += content[i]
                i += 1
            result.append(int(hex_s, 16) if hex_s else 0)
            continue
        elif esc in '01234567':
            oct_s = esc
            i += 1
            while i < len(content) and content[i] in '01234567' and len(oct_s) < 3:
                oct_s += content[i]
                i += 1
            result.append(int(oct_s, 8) & 0xFF)
            continue
        else:
            result.append(ord(esc) & 0xFF)
        i += 1
    return bytes(result)


# ---------------------------------------------------------------------------
# State-machine string finder
# ---------------------------------------------------------------------------

def find_strings(src):
    """
    Walk C source with a state machine, returning list of (start, end, depth)
    for every string literal.  Correctly skips block/line comments and char
    literals so quoted text inside them is never reported.
    """
    results = []
    i = 0
    n = len(src)
    depth = 0

    while i < n:
        c = src[i]

        # Block comment
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            i += 2
            while i < n:
                if src[i] == '*' and i + 1 < n and src[i + 1] == '/':
                    i += 2
                    break
                i += 1
            continue

        # Line comment
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            while i < n and src[i] != '\n':
                i += 1
            continue

        # Char literal
        if c == "'":
            i += 1
            while i < n:
                if src[i] == '\\':
                    i += 2
                elif src[i] == "'":
                    i += 1
                    break
                else:
                    i += 1
            continue

        # String literal
        if c == '"':
            start = i
            i += 1
            while i < n:
                if src[i] == '\\':
                    i += 2
                elif src[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            results.append((start, i, depth))
            continue

        if c == '{':
            depth += 1
        elif c == '}':
            depth = max(0, depth - 1)
        i += 1

    return results


def group_adjacent(strings, src):
    """
    Merge runs of adjacent string literals (C implicit concatenation).
    Two literals are adjacent when only whitespace separates them.
    Returns list of (group_start, group_end, depth) where depth is that of
    the first literal in the group.
    """
    if not strings:
        return []
    groups = []
    i = 0
    while i < len(strings):
        gstart, gend, gdepth = strings[i]
        while i + 1 < len(strings):
            nstart, nend, _ = strings[i + 1]
            if src[gend:nstart].strip() == '':
                gend = nend
                i += 1
            else:
                break
        groups.append((gstart, gend, gdepth))
        i += 1
    return groups


# ---------------------------------------------------------------------------
# Context analysis helpers
# ---------------------------------------------------------------------------

def line_of(src, pos):
    """Return the full text of the line containing pos."""
    start = src.rfind('\n', 0, pos)
    start = start + 1 if start >= 0 else 0
    end = src.find('\n', pos)
    end = end if end >= 0 else len(src)
    return src[start:end]


def stmt_before(src, pos):
    """
    Return the text of the C statement immediately before pos.
    Scans back to the nearest ;, {, or } at the same nesting level.
    """
    i = pos - 1
    while i >= 0 and src[i] in ' \t\r\n':
        i -= 1
    while i >= 0:
        if src[i] in (';', '{', '}'):
            break
        i -= 1
    return src[i + 1:pos]


def is_in_static_init(src, pos):
    """
    Return True if pos falls inside any { ... } block that is an initializer
    (preceded by '=') of a declaration containing 'static'.

    Handles both file-scope:
        static const char *arr[] = { "str1", "str2" };
    and function-scope nested struct arrays:
        static const struct {...} methods[] = { {"str", id}, ... };
    """
    rel_depth = 0
    i = pos - 1

    while i >= 0:
        c = src[i]

        if c == '}':
            rel_depth += 1
        elif c == '{':
            if rel_depth > 0:
                rel_depth -= 1
            else:
                # Enclosing '{' — find what immediately precedes it (skip whitespace)
                j = i - 1
                while j >= 0 and src[j] in ' \t\n\r':
                    j -= 1

                if j < 0:
                    return False

                prec = src[j]

                if prec == '=':
                    # This { is an initializer block.  Scan backward to find the
                    # declaration text between the previous ';' (or enclosing '{')
                    # and this '='.  Skip over any nested { } in the declaration
                    # (e.g. struct type definition).
                    k = j - 1
                    inner = 0
                    while k >= 0:
                        ck = src[k]
                        if ck == '}':
                            inner += 1
                        elif ck == '{':
                            if inner > 0:
                                inner -= 1
                            else:
                                break  # enclosing block, stop
                        elif ck == ';' and inner == 0:
                            break
                        k -= 1
                    decl = src[k + 1:j]
                    if re.search(r'\bstatic\b', decl):
                        return True
                    # Not static — keep scanning outward in case we're nested
                    # deeper (e.g. non-static outer struct containing a string).
                    i = k
                    rel_depth = 0
                    continue

                elif prec in (',', '{'):
                    # This { is a struct/array element initializer inside an
                    # outer initializer block.  Step over it and keep scanning.
                    i = j
                    continue

                else:
                    # Regular block opener (function body, if/for, etc.)
                    return False

        elif c == ';':
            if rel_depth == 0:
                return False

        i -= 1

    return False


def should_skip(src, start, end, depth):
    """Return True if the string group at [start,end) must not be obfuscated."""
    # Empty group or empty first literal
    if end - start <= 2:
        return True
    first_close = src.find('"', start + 1)
    if first_close < 0 or src[start + 1:first_close] == '':
        # Only skip if the ENTIRE group is effectively empty
        span_content = STRING_RE.findall(src[start:end])
        if not any(lit[1:-1] for lit in span_content):
            return True

    # File scope
    if depth == 0:
        return True

    # Preprocessor line
    if line_of(src, start).lstrip().startswith('#'):
        return True

    # 'static' keyword visible in the immediately-enclosing statement
    stmt = stmt_before(src, start)
    if re.search(r'\bstatic\b', stmt):
        return True

    # char array initializer: char foo[] = or char foo[N] =
    if re.search(r'\bchar\s+\w+\s*\[', stmt):
        return True

    # sizeof() argument
    if re.search(r'\bsizeof\s*\(\s*$', stmt):
        return True

    # Inside a static initializer at any nesting depth
    if is_in_static_init(src, start):
        return True

    # String used as argument to a macro (likely does string concatenation).
    # Detect: MACRO_NAME( ... "string  where MACRO_NAME is uppercase/underscore.
    # Scan backward from start, skip whitespace and '(', look for identifier.
    j = start - 1
    while j >= 0 and src[j] in ' \t\n\r':
        j -= 1
    if j >= 0 and src[j] == '(':
        j -= 1
        while j >= 0 and src[j] in ' \t':
            j -= 1
        k = j
        while k >= 0 and (src[k].isalnum() or src[k] == '_'):
            k -= 1
        macro_name = src[k + 1:j + 1]
        if macro_name and re.match(r'^[A-Z_][A-Z0-9_]*$', macro_name):
            return True

    return False


# ---------------------------------------------------------------------------
# Encryption + replacement
# ---------------------------------------------------------------------------

def make_replacement(src_span, key):
    """
    Extract bytes from all C string literal(s) in src_span and return a
    _S(n,...) replacement, or None on failure.
    Handles single literals and adjacent-literal groups.
    """
    raw = b''
    for m in STRING_RE.finditer(src_span):
        content = m.group(0)[1:-1]
        try:
            raw += parse_c_string(content)
        except Exception:
            return None
    if not raw:
        return None
    enc = [(b ^ key) & 0xFF for b in raw]
    return '_S({},{})'.format(len(enc), ','.join('0x{:02x}'.format(b) for b in enc))


def obfuscate(src, key):
    """Replace eligible string literals with _S() calls. Returns (new_src, count)."""
    strings = find_strings(src)
    groups = group_adjacent(strings, src)

    subs = []
    for start, end, depth in groups:
        if should_skip(src, start, end, depth):
            continue
        repl = make_replacement(src[start:end], key)
        if repl is None:
            continue
        subs.append((start, end, repl))

    # Apply in reverse order to preserve earlier positions
    result = list(src)
    for start, end, repl in reversed(subs):
        result[start:end] = list(repl)
    return ''.join(result), len(subs)


# ---------------------------------------------------------------------------
# Header update
# ---------------------------------------------------------------------------

def write_strenc_h(key):
    path = os.path.join(SCRIPT_DIR, 'headers', 'strenc.h')
    with open(path, 'w') as f:
        f.write('#pragma once\n')
        f.write('\n')
        f.write('/* Per-build XOR key -- regenerated by obfstr.py each build */\n')
        f.write('#ifndef _SKY\n')
        f.write('#define _SKY 0x{:02x}\n'.format(key))
        f.write('#endif\n')
        f.write('\n')
        f.write('static inline const char *_xds(const unsigned char *e, int n, char *d) {\n')
        f.write('    int i;\n')
        f.write('    for (i = 0; i < n; i++) d[i] = (char)((unsigned char)e[i] ^ (unsigned char)_SKY);\n')
        f.write('    d[n] = \'\\0\';\n')
        f.write('    return d;\n')
        f.write('}\n')
        f.write('\n')
        f.write('/* Decrypt n XOR-encrypted bytes onto the stack; lifetime tied to enclosing function */\n')
        f.write('#define _S(n, ...) _xds((const unsigned char[]){__VA_ARGS__}, (n), (char *)__builtin_alloca((n) + 1))\n')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print('Usage: obfstr.py file1.c [file2.c ...]', file=sys.stderr)
        sys.exit(1)

    files = sys.argv[1:]
    key = random.randint(1, 255)

    write_strenc_h(key)

    obf_dir = os.path.join(SCRIPT_DIR, 'obf')
    os.makedirs(obf_dir, exist_ok=True)

    total = 0
    for fname in files:
        bname = os.path.basename(fname)
        src_path = fname if os.path.isabs(fname) else os.path.join(SCRIPT_DIR, fname)
        dst_path = os.path.join(obf_dir, bname)

        with open(src_path, errors='replace') as f:
            src = f.read()

        if bname in SKIP_FILES:
            with open(dst_path, 'w') as f:
                f.write(src)
            print('  {}: skipped (copy)'.format(bname))
            continue

        obfuscated, n = obfuscate(src, key)
        total += n

        with open(dst_path, 'w') as f:
            f.write(obfuscated)
        print('  {}: {} strings obfuscated'.format(bname, n))

    print('obfstr: key=0x{:02x}  total={} strings -> obf/'.format(key, total))


if __name__ == '__main__':
    main()
