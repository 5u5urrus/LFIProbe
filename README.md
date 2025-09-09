# LFIProbe  

**LFIProbe** is a focused tester for detecting Local File Inclusion (LFI), file disclosure, and PHP wrapper vulnerabilities. It fuzzes parameters with payloads, classifies responses against a baseline.  

## Features  
- 🎯 Detects LFI, LFD, and PHP wrapper behaviors  
- 📂 Smart candidate generation (traversals, sensitive files, wrappers)  
- 🧩 Response classification (baseline/template vs. deltas)  
- 🔎 Auto-detects and decodes Base64 `php://filter` leaks  
- 💾 Saves interesting responses for offline analysis  
- ⚡ Verbose, clean, and easy to use  

## Output classification  
When testing, **LFIProbe** assigns a verdict tag to each request:  

- **BASELINE** – The original page as requested (used for comparison).  
- **TEMPLATE** – Response looks like the app’s “not found” or placeholder page.  
- **UNKNOWN** – Response is very close to the template (length or hash), but not identical.  
- **DELTA** – Response is meaningfully different (possible LFI indicator).  
- **ERROR** – The request failed (timeout, network error, etc.).  

Additionally, when a `php://filter` payload returns a Base64-encoded blob that looks like source code, **LFIProbe** automatically decodes and saves it.  

## Usage  
```bash
python3 lfiprobe.py http://target.local/index.php?op=home -p op
````

### Options

* `-p, --param` — Parameter to fuzz (default: `op`)
* `-t, --timeout` — HTTP timeout seconds (default: 8.0)
* `-H, --header` — Extra header (e.g., `Cookie: PHPSESSID=abc`)
* `-o, --outdir` — Directory to save responses (default: `evidence`)
* `--list` — Print clean URLs as they are tested
* `-v, --verbose` — Verbose output

## Example

```bash
python3 lfiprobe.py http://192.168.56.102/app.php?op=home -p op -v
```

Sample output:

```
[baseline] code=200 len=4523 hash=7d9f...
[template] code=404 len=1234 hash=a1b2... url=http://192.168.56.102/app.php?op=___no_such_page___
[DELTA    ] http://192.168.56.102/app.php?op=../../../../etc/passwd  [200]  body=1728
[DECODE   ] -> evidence/1694356123_config.decoded.txt

Done. Interesting responses saved: 3 -> evidence
```

## Notes

* Works with both Linux and Windows target paths
* Includes traversal, wrapper, and behavior probe payloads
* Ideal for pentests and CTFs where LFI is suspected

## License

MIT License.

## Author

Vahe Demirkhanyan

```

Would you like me to also add a **“Payloads included”** section in the README, listing the main categories (traversals, sensitive files, wrappers, probes), so people know exactly what LFIProbe is fuzzing with?
```
