# Contributing to Yash XSS Framework

First off, thanks for taking the time to contribute! 🎉

We actively encourage security researchers to improve our custom `payloads.py` library and core GUI features. Here is how you can submit your own payloads or engines to the framework:

## Adding New XSS Payloads
1. Fork the repository on GitHub.
2. Edit `payloads.py`.
3. If you have an advanced Context-specific payload (e.g., an evasion for CloudFlare), add it to `CONTEXT_PAYLOAD_MAP` under the correct reflection context like `"html_attribute_quoted"`.
4. If it's a general heuristic payload, append it to `GENERIC_PAYLOADS`.
5. Keep it sorted by effectiveness. Avoid bloated 1,000-line fuzz lists; we only want surgical, neural-driven obfuscation vectors.
6. Create a Pull Request!

## Working on the App
- Code is formatted strictly for Python 3.8+.
- PRs that modify `yash_xss_gui.py` must ensure the **Check Updates** button remains functional, and `html.escape()` is strictly used when rendering target URLs and payloads into the local `report.html`.

Thank you for contributing to open source security!
