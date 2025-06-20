# 🔐 IPA Secret Scanner

A Python tool to scan extracted iOS IPA packages (or directories) for secrets such as API keys, access tokens, credentials, and more. It generates a categorized, collapsible, dark-themed HTML report for easier analysis and sharing.

## 🚀 Features

- 🔍 Detects common secrets using regex (API keys, tokens, JWT, AWS keys, Stripe keys, etc.)
- 🧠 Decodes and filters Base64-encoded values
- 🧾 Extracts and scans human-readable strings from binary files
- ⚠️ Flags sensitive file extensions like `.pem`, `.key`, `.crt`
- 🔐 Highlights code obfuscation hints (Proguard, R8)
- 📁 Supports `.ipa` file extraction and direct folder scanning
- 📄 Generates clean, styled, mobile-friendly HTML reports
- 🧪 Skips known non-sensitive files (e.g., images, fonts, CSS)

## 📂 Input Options

You can either:
- Pass an `.ipa` file with `--ipa`
- Scan a pre-extracted directory with `--dir`

## 🖥️ Usage

```bash
# From an IPA file:
python ipa_scanner.py --ipa MyApp.ipa

# From an already extracted directory:
python ipa_scanner.py --dir ./MyAppPayload

# Output report (default is `scan_report.html`)
python ipa_scanner.py --ipa MyApp.ipa --output my_report.html
````

## 📊 Output

* An HTML report named `scan_report.html` (or custom file)
* Shows secrets grouped by type and file
* Highlights:

  * Sensitive Base64 values (decoded)
  * Obfuscation hints
  * Binary file secrets (in a special section)
  * Sensitive file extensions found

## ⚠️ Known Limitations

* ❌ No recursive Base64 decoding
* 🔍 No advanced false positive filtering
* 🐢 Scans large IPAs/directories slowly (no threading)
* 📄 Report only in HTML (no CSV/PDF/JSON export)
* 🧠 Obfuscation detection is basic (keyword match)
* 🧪 No CI/CD integration (yet)

## 📦 Requirements

* Python 3.6+
* `tqdm`

Install via:

```bash
pip install tqdm
```

## 📜 License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

---

**Author**: Shyam Chauhan
**Disclaimer**: Use only for ethical and authorized security assessments.

