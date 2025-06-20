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

## ⚠️ Disclaimer
For educational and authorized security testing purposes only.
---

## Author

- [@shyam-chuahan](https://github.com/shyam-chauhan)


## Repository link
- https://github.com/shyam-chauhan/anti_malware/

## Like my work ?

Give repository 🌟

<h3 align="left">Connect with me:</h3>
<p align="left">
<a href="https://linkedin.com/in/chauhan-shyam009" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="chauhan-shyam009" height="30" width="40" /></a>
<a href="https://t.me/chauhan_shyam">
    <img align="left" alt="Shyam chauhan Telegram" width="34px" src="https://raw.githubusercontent.com/gauravghongde/social-icons/master/SVG/Color/Telegram.svg" />
</a>
</p>

<h3 align="left">Buy me a coffee :</h3>
<p><a href="https://www.buymeacoffee.com/shyam_chauhan"> <img align="left" src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="shyam_chauhan" /></a></p><br><br><br>


