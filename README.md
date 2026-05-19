# phishing-mail-analyzer

A rule-based phishing email analyzer written in Python. No ML — pure regex and scoring logic.

## What it does

Analyzes email text and assigns a risk score based on predefined rules. Checks for:

- Suspicious keywords (urgent, verify, suspended, gift card, etc.)
- URL analysis — HTTP vs HTTPS, IP-based links, URL shorteners, long paths, non-standard ports
- Domain inspection — suspicious TLDs, excessive subdomains, typosquatting (paypa1, amaz0n, etc.)
- Subject line analysis — ALL CAPS, excessive punctuation, pressure phrases
- Free email domain misuse — Gmail sender claiming to be a bank or Microsoft
- Risky attachment mentions — .exe, .bat, .vbs, enable macros, etc.
- Base64 blob detection — possible hidden payload

## Risk levels

`LOW` / `MEDIUM` / `HIGH` / `CRITICAL` — based on total score.

## Usage

```bash
cd phishing_email_analyzer
python main.py suspicious_email.txt
```

Or with stdin:
```bash
cat email.txt | python main.py
```

Skip DNS lookup:
```bash
python main.py email.txt --no-dns
```
