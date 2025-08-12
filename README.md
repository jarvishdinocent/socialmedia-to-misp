# SocialMedia-to-MISP

**SocialMedia-to-MISP** is a Python automation tool that collects Indicators of Compromise (IOCs) from various social media and OSINT sources, validates them using VirusTotal, and ingests the confirmed malicious IOCs into a [MISP](https://www.misp-project.org/) instance.

It is designed for security analysts and threat hunters who want to **continuously enrich their MISP with community-sourced, actionable threat intelligence** — without drowning in false positives or duplicates.

---

## 📌 Supported Sources

You can enable or disable each source at the top of the script.

| Source                     | Description                                                | Requirements                            |
| -------------------------- | ---------------------------------------------------------- | --------------------------------------- |
| **Reddit**                 | Monitors selected security-related subreddits.             | Reddit API credentials                  |
| **Telegram**               | Monitors selected threat intel channels.                   | Telegram API credentials                |
| **RSS Feeds**              | Pulls from blogs, CERT advisories, vendor feeds.           | None                                    |
| **Mastodon**               | Reads public hashtag timelines from any Mastodon instance. | None                                    |
| **GitHub**                 | Scans issues/releases in selected repos for IOCs.          | Optional GitHub token for higher limits |
| **YouTube**                | Reads titles/descriptions from specified channels.         | YouTube Data API key                    |
| **Twitter/X** *(optional)* | Queries tweets using `snscrape` (no API key needed).       | Install `snscrape` locally              |

---

## ✨ Features

* **Multi-source collection** — Fetches from different OSINT and social platforms.
* **Regex IOC extraction** — Detects URLs, IP addresses, and domains.
* **VirusTotal validation** — Keeps only IOCs flagged as malicious.
* **MISP deduplication** — Skips IOCs already stored in your instance.
* **Automatic tagging** — Tags events with `osint` and the source name.
* **Configurable sources** — Toggle platforms without code changes.

---

## ⚙️ Requirements

* **Python 3.8+**
* **MISP instance** with API key
* **API keys**:

  * Reddit ([PRAW Quickstart](https://praw.readthedocs.io/en/latest/getting_started/quick_start.html))
  * Telegram ([Telethon Auth Guide](https://docs.telethon.dev/en/stable/basic/signing-in.html))
  * VirusTotal ([API key signup](https://www.virustotal.com/gui/join-us))
  * Optional: GitHub token, YouTube Data API key
* For Twitter/X scraping: [`snscrape`](https://github.com/JustAnotherArchivist/snscrape) installed

---

## 📥 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/jarvishdinocent/socialmedia-to-misp.git
cd socialmedia-to-misp
pip install -r requirements.txt
```
```Tip: Use a virtual environment:
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

