# ipa_scanner_optimized.py

"""
IPA Scanner Optimized

Features:
- Scans IPA files or extracted directories for sensitive information and credentials.
- Detects sensitive hardcoded values (API keys, secrets, passwords, tokens, etc.).
- Decodes Base64 strings and extracts embedded secrets (text files only).
- Lists potentially sensitive files (e.g., .pem, .key, .crt).
- Identifies permission usage based on Info.plist and code keywords.
- Detects signs of code obfuscation (e.g., ProGuard, R8).
- Extracts strings from binary files (extensionless) without Base64 decoding.
- Generates a structured, collapsible, dark-themed HTML report with categorized findings.

Files scanned:
- All text-based files (e.g., .m, .swift, .plist, .json, .xml, etc.)
- Extensionless binary files (scanned via ASCII strings, no Base64 decode)
- Excludes binary/media/CSS files (e.g., .png, .jpg, .css, etc.)
"""

import os
import re
import base64
import zipfile
import argparse
import logging
import plistlib
from tqdm import tqdm
from datetime import datetime
from html import escape

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

SENSITIVE_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase Key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws(?:.{0,20})?(?:secret|private)?(?:.{0,20})?['\"][^\s'\"]{40,}['\"]",
    "Stripe Live Secret Key": r"sk_live_[0-9a-zA-Z\/]{24,}",
    "Stripe Test Secret Key": r"sk_test_[0-9a-zA-Z\/]{24,}",
    "Stripe Publishable Key": r"pk_(?:test|live)_[0-9a-zA-Z\/]{24,}",
    "Stripe Webhook Secret": r"whsec_[0-9a-zA-Z]{32,}",
    "PayPal Client ID": r"A[a-zA-Z0-9]{79,}",
    "PayPal Secret": r"(?i)(?:paypal.*secret)[\s:=\"']+[^\x00-\x1F\x7F<>]{32,}",
    "PayPal Access Token": r"access_token\\$production\\$[a-zA-Z0-9\-_]{100,}",
    "PayPal Email": r"[a-zA-Z0-9_.+-]+@paypal\\.com",
    "PayPal Webhook URL": r"https:\/\/api\\.paypal\\.com\/v1\/notifications\/webhooks",
    "PayPal Sandbox Credentials": r"(?:sandbox|test)\.paypal\.com",
    "Generic API Key": r"(?i)(?:api|apikey|secret|token)[\s:=\"']{1,3}[^\s\"'<>]{16,}",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|PGP|PRIVATE) KEY-----",
    "JWT": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Username": r"(?i)(username|user|uname)[\s:=\"']+[a-zA-Z0-9._-]{3,}[^\n]*",
    "Password": r"(?i)(password|passwd|pwd)[\s:=\"']+[a-zA-Z0-9!@#$%^&*()_+=\-]{4,}[^\n]*",
}

COMPILED_PATTERNS = {k: re.compile(v) for k, v in SENSITIVE_PATTERNS.items()}
BASE64_REGEX = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")

EXCLUDED_EXTENSIONS = ['.css', '.scss', '.png', '.jpg', '.jpeg', '.gif', '.svg']
COMMON_DEV_KEYWORDS = ['font-size', 'margin', 'padding', 'display', 'position']
SENSITIVE_FILE_EXTENSIONS = ['.pem', '.key', '.crt', '.cer', '.pfx']

PERMISSION_KEYWORDS = [
    "NSCameraUsageDescription", "NSLocationWhenInUseUsageDescription",
    "NSLocationAlwaysUsageDescription", "NSMicrophoneUsageDescription",
    "NSPhotoLibraryUsageDescription", "NSBluetoothAlwaysUsageDescription"
]

OBFUSCATION_HINTS = ['obfuscator', 'proguard', 'r8', 'minifyenabled']


def is_text_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return all(32 <= b <= 126 or b in (9, 10, 13) for b in chunk)
    except:
        return False


def looks_like_dev_code(text):
    return any(k in text.lower() for k in COMMON_DEV_KEYWORDS)


def try_base64_decode(text):
    try:
        padding = '=' * (-len(text) % 4)
        decoded = base64.b64decode(text + padding).decode('utf-8')
        if decoded and not looks_like_dev_code(decoded):
            return decoded
    except Exception:
        return None
    return None


def extract_strings_from_binary(file_path, min_length=4):
    result = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            strings = re.findall(rb"[ -~]{%d,}" % min_length, data)
            result = [s.decode("utf-8", errors="ignore") for s in strings]
    except Exception as e:
        logging.warning(f"Failed to extract strings from binary: {file_path} - {e}")
    return "\n".join(result)


def scan_content(content, decode_base64=True):
    sensitive_matches, base64_matches = [], []
    for label, pattern in COMPILED_PATTERNS.items():
        for match in pattern.findall(content):
            if isinstance(match, tuple):
                match = next((m for m in match if m), '')
            if not looks_like_dev_code(match):
                sensitive_matches.append((label, match.strip()))
    if decode_base64:
        for b64 in BASE64_REGEX.findall(content):
            decoded = try_base64_decode(b64.strip())
            if decoded:
                base64_matches.append((b64.strip(), decoded.strip()))
    return sensitive_matches, base64_matches


def parse_info_plist(plist_path):
    try:
        with open(plist_path, 'rb') as f:
            plist = plistlib.load(f)
        permissions = {k: v for k, v in plist.items() if k in PERMISSION_KEYWORDS}
        return permissions
    except:
        return {}


def scan_directory(directory):
    all_findings = []
    sensitive_files = []
    permissions = set()
    obfuscation_signals = set()

    for root, _, files in os.walk(directory):
        for file in tqdm(files, desc=f"Scanning {root}", leave=False):
            ext = os.path.splitext(file)[1].lower()
            full_path = os.path.join(root, file)

            if ext in SENSITIVE_FILE_EXTENSIONS:
                sensitive_files.append(full_path)

            if ext in EXCLUDED_EXTENSIONS:
                continue

            if is_text_file(full_path):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if file == "Info.plist":
                            perms = parse_info_plist(full_path)
                            permissions.update(perms.keys())
                        for obf in OBFUSCATION_HINTS:
                            if obf.lower() in content.lower():
                                obfuscation_signals.add(obf)
                        sensitive, base64s = scan_content(content, decode_base64=True)
                        if sensitive or base64s:
                            all_findings.append((full_path, sensitive, base64s))
                except Exception as e:
                    logging.warning(f"Error reading {full_path}: {e}")

            elif ext == '':
                content = extract_strings_from_binary(full_path)
                if content:
                    sensitive, _ = scan_content(content, decode_base64=False)
                    if sensitive:
                        all_findings.append((full_path + " (binary)", sensitive, []))

    return all_findings, sensitive_files, permissions, bool(obfuscation_signals)


def unzip_ipa(ipa_path, extract_dir):
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)


def categorize(findings):
    categories = {}
    for file, sensitive, _ in findings:
        for label, val in sensitive:
            if label not in categories:
                categories[label] = []
            categories[label].append((file, val))
    return categories, findings


def generate_html_report(findings, output_file, sensitive_files, permissions, obfuscated, target):
    categories, _ = categorize(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = ["<html><head><title>Scan Report</title><style>",
            "body{font-family:Arial;background:#121212;color:#e0f7fa;}",
            "details{margin:1em 0;}summary{cursor:pointer;font-size:1.2em;color:#4dd0e1;}",
            "table{border-collapse:collapse;width:100%;margin-top:10px;}",
            "th,td{border:1px solid #555;padding:8px;}th{background:#0288d1;color:white;}",
            "code{color:#81d4fa;word-wrap:break-word;}",
            "</style></head><body>",
            f"<h1>{target} Scan Report</h1><p>Generated on: {now}</p>"]

    html.append(f"<p><strong>Permissions Used:</strong> {', '.join(sorted(permissions)) if permissions else 'None'}</p>")
    html.append(f"<p><strong>Code Obfuscation Detected:</strong> {'Yes' if obfuscated else 'No'}</p>")

    if sensitive_files:
        html.append(f'<details open><summary>Sensitive Files Detected ({len(sensitive_files)})</summary><ul>')
        for file in sensitive_files:
            html.append(f"<li>{escape(file)}</li>")
        html.append("</ul></details>")

    for label, matches in categories.items():
        html.append(f'<details><summary>{escape(label)} ({len(matches)})</summary>')
        html.append("<table><tr><th>File</th><th>Value</th></tr>")
        for file, val in matches:
            html.append(f"<tr><td>{escape(file)}</td><td><code>{escape(val)}</code></td></tr>")
        html.append("</table></details>")

    for file, _, base64s in findings:
        if base64s:
            html.append(f'<details><summary>Base64 Strings in {escape(file)} ({len(base64s)})</summary>')
            html.append("<table><tr><th>Encoded</th><th>Decoded</th></tr>")
            for enc, dec in base64s:
                html.append(f"<tr><td><code>{escape(enc)}</code></td><td><code>{escape(dec)}</code></td></tr>")
            html.append("</table></details>")

    html.append("</body></html>")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(html))


def main():
    parser = argparse.ArgumentParser(description="IPA/Directory Scanner for Secrets")
    parser.add_argument("--ipa", help="Path to IPA file")
    parser.add_argument("--dir", help="Path to directory")
    parser.add_argument("--output", default="scan_report.html", help="HTML report output file")
    args = parser.parse_args()

    if not args.ipa and not args.dir:
        logging.error("Provide either --ipa or --dir")
        return

    if args.ipa:
        extract_to = "./extracted_ipa"
        os.makedirs(extract_to, exist_ok=True)
        logging.info("Unzipping IPA...")
        unzip_ipa(args.ipa, extract_to)
        target = extract_to
    else:
        target = args.dir

    logging.info("Scanning files...")
    findings, sensitive_files, permissions, obfuscated = scan_directory(target)
    generate_html_report(findings, args.output, sensitive_files, permissions, obfuscated, target)
    logging.info(f"Scan complete! Report saved to {args.output}")


if __name__ == '__main__':
    main()
