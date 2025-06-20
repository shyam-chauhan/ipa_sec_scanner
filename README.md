Here’s a **GitHub-friendly README** you can copy-paste directly into your repo for the **IPA Scanner Optimized** tool:

---

# 📱 IPA Scanner Optimized

A powerful CLI tool for scanning **IPA files** or **extracted directories** for sensitive data, secrets, hardcoded credentials, permissions, and signs of obfuscation. It generates a structured and dark-themed **HTML report** for easy analysis.

---

## 🚀 Features

* 🔍 Scans IPA files or folders for:

  * API keys, secrets, tokens, credentials
  * Base64-encoded secrets (text files only)
  * Sensitive files like `.pem`, `.key`, `.crt`
  * iOS permission usage (`Info.plist`, code indicators)
  * Signs of code obfuscation (e.g., ProGuard, R8)
  * Strings from **extensionless binary files** (IPA-specific)
* 🗂 Excludes irrelevant files (`.png`, `.jpg`, `.css`, etc.)
* 📄 Outputs a **collapsible dark-themed HTML report**
* ✅ Fully CLI-based, fast and easy to integrate into workflows

---

## 📂 Files Scanned

* `.m`, `.swift`, `.plist`, `.json`, `.xml`, and similar text-based files
* Binary files with **no extension** (scanned using `strings`-like extraction)
* Skips CSS/images/media files to reduce noise

---

## 📦 Installation

No installation needed. Just clone and run with Python 3:

```bash
git clone https://github.com/shyam-chauhan/ipa_sec_scanner
cd ipa_sec_scanner
pip install -r requirements.txt
```

---

## 🧑‍💻 Usage

### 1. Scan an IPA file:

```bash
python ipa_scanner.py --ipa /path/to/app.ipa
```

### 2. Scan an extracted directory:

```bash
python ipa_scanner.py --dir /path/to/extracted_folder
```

### 3. Custom HTML output file:

```bash
python ipa_scanner.py --ipa app.ipa --output results.html
```

The tool will unzip the IPA (if applicable), scan files, and generate a clean and readable HTML report like:


---

## 📌 Report Highlights

* **Permissions used**
* **Sensitive data categories** like API keys, secrets, credentials
* **Base64 strings** with decoded values
* **Sensitive file detection**
* **Obfuscation detection**

---

## 🔐 Patterns Detected

Some examples include:

* 🔑 Google/Firebase API Keys
* 🛡️ AWS Keys
* 💳 Stripe Secrets
* 💰 PayPal Credentials
* 🔐 JWTs, private keys, Slack tokens
* 👤 Hardcoded usernames & passwords
* 🧬 Base64-encoded secrets

---

## 🛠 Developer Notes

* Written in pure Python 3
* Uses `tqdm` for progress display
* Uses `plistlib` for Info.plist parsing
* No external binary dependencies (like `strings`) required

---


---

## 🙌 Contributing

Pull requests, suggestions, and bug reports are welcome! Open an issue or fork and improve.

---

## 👤 Author

Developed by [Shyam Chauhan](https://github.com/shyam-chauhan)

---

