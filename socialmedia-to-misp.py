import praw
import re
import requests
from pymisp import PyMISP, MISPEvent, MISPAttribute
from datetime import datetime, timezone
from telethon.sync import TelegramClient
from telethon.tl.functions.messages import GetHistoryRequest
import urllib3
import html
import time
import json
import subprocess
import feedparser  # RSS
# Mastodon: we’ll use public endpoints via requests (no auth)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---- CONFIGURATION ----
# Toggle sources on/off
ENABLE_REDDIT   = True
ENABLE_TELEGRAM = True
ENABLE_RSS      = True
ENABLE_MASTODON = True
ENABLE_GITHUB   = True
ENABLE_YOUTUBE  = True
ENABLE_TWITTER  = False  # requires `snscrape` installed locally

# Reddit
REDDIT_CLIENT_ID = 'YOUR_REDDIT_CLIENT_ID'
REDDIT_CLIENT_SECRET = 'YOUR_REDDIT_CLIENT_SECRET'
REDDIT_USER_AGENT = 'YOUR_USER_AGENT'
SUBREDDITS = [
    'ThreatIntel', 'netsec', 'malware', 'osint',
    'reverseengineering', 'hacking', 'infosec', 'cybercrime'
]

# Telegram
TELEGRAM_API_ID = 'YOUR_TELEGRAM_API_ID'
TELEGRAM_API_HASH = 'YOUR_TELEGRAM_API_HASH'
TELEGRAM_PHONE = 'YOUR_TELEGRAM_PHONE_NUMBER'
TELEGRAM_CHANNELS = [
    'vxunderground', 'MalwareResearch', 'cyberintelligence'
]

# RSS (add any feeds you trust)
RSS_FEEDS = [
    'https://www.reddit.com/r/netsec/.rss',
    'https://www.reddit.com/r/ThreatIntel/.rss'
    # add vendor intel blogs, CERT advisories, etc.
]

# Mastodon public hashtag timelines (no auth; per-instance)
# Each entry: (base_instance_url, hashtag_without_hash, limit)
MASTODON_HASHTAGS = [
    ('https://infosec.exchange', 'malware', 40),
    ('https://hachyderm.io', 'threatintel', 40)
]

# GitHub: list of repos to scan recent issues/releases for IOCs
# Format "owner/repo"
GITHUB_REPOS = [
    'vxunderground/MalwareSourceCode',
    'MISP/MISP'
]
# Optional: GitHub token for higher rate limits (leave empty to use unauth)
GITHUB_TOKEN = ''  # 'ghp_...'

# YouTube (Data API v3) — channel IDs to scan recent video titles/descriptions
YOUTUBE_API_KEY = ''  # required if ENABLE_YOUTUBE=True
YOUTUBE_CHANNEL_IDS = [
    # examples (replace with your sources)
    # 'UC0ArlFuFYMpEewyRBzdLHiw'  # Google Cloud Tech (example)
]

# Twitter/X via snscrape (no API key; best-effort, may break/change)
# Provide queries (hashtags, from:user, keywords)
TWITTER_QUERIES = [
    'malware since:2025-07-01',
    'threatintel since:2025-07-01'
]
SNSCRAPE_PATH = 'snscrape'  # ensure available in PATH

# MISP
MISP_URL = 'https://YOUR_MISP_INSTANCE'
MISP_KEY = 'YOUR_MISP_API_KEY'
MISP_VERIFY_CERT = False

# VirusTotal (same behavior as your original script)
VT_HEADERS = {"x-apikey": "YOUR_VIRUSTOTAL_API_KEY"}
VT_URL = 'https://www.virustotal.com/api/v3/urls'


# ---- CORE (unchanged pipeline) ----
def init_misp():
    return PyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_CERT)

def extract_iocs(text):
    return re.findall(
        r'(https?://[^\s\)\]]+|(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[A-Za-z]{2,})',
        text or ""
    )

def check_virustotal(ioc):
    try:
        r = requests.post(VT_URL, headers=VT_HEADERS, data={"url": ioc})
        if r.status_code != 200:
            return False
        vid = r.json()['data']['id']
        analysis = requests.get(f"{VT_URL}/{vid}", headers=VT_HEADERS).json()
        stats = analysis['data']['attributes']['last_analysis_stats']
        return stats.get("malicious", 0) > 0
    except:
        return False

def is_duplicate(misp, ioc):
    try:
        return bool(misp.search(controller="attributes", value=ioc).get("Attribute"))
    except:
        return False

def get_attr_type(ioc):
    if ioc.startswith("http"):
        return "url"
    if re.match(r"(?:\d{1,3}\.){3}\d{1,3}", ioc):
        return "ip-dst"
    return "domain"

def ingest_to_misp(iocs, source_name):
    misp = init_misp()
    valid = []
    for i in iocs:
        if is_duplicate(misp, i): 
            continue
        if not check_virustotal(i): 
            continue
        valid.append(i)

    if not valid:
        print(f"[INFO] No malicious IOCs found from {source_name}.")
        return

    event = MISPEvent()
    event.distribution = 1
    event.analysis = 2
    event.threat_level_id = 2
    event.info = f"Advanced Threat Feed: OSINT Insights – {datetime.now(timezone.utc):%Y-%m-%d}"
    event.published = True
    event.add_tag("osint")
    event.add_tag(source_name.lower())

    for i in valid:
        attr = MISPAttribute()
        attr.type = get_attr_type(i)
        attr.value = i
        attr.comment = f"Source: {source_name}"
        event.add_attribute(**attr)

    misp.add_event(event)
    print(f"[✓] Ingested {len(valid)} malicious IOCs from {source_name}")


# ---- REDDIT (unchanged) ----
def fetch_reddit_feeds():
    print("[INFO] Fetching from Reddit...")
    rd = praw.Reddit(client_id=REDDIT_CLIENT_ID,
                     client_secret=REDDIT_CLIENT_SECRET,
                     user_agent=REDDIT_USER_AGENT)
    iocs = []
    for sub in SUBREDDITS:
        print(f"  → r/{sub}")
        try:
            for post in rd.subreddit(sub).new(limit=25):
                iocs.extend(extract_iocs(post.title))
                iocs.extend(extract_iocs(post.selftext))
        except:
            pass
        time.sleep(0.5)
    print(f"[DEBUG] Extracted {len(set(iocs))} unique IOCs from Reddit")
    return list(set(iocs))


# ---- TELEGRAM (unchanged) ----
def fetch_telegram_feeds():
    print("[INFO] Fetching from Telegram...")
    iocs = []
    with TelegramClient('session', TELEGRAM_API_ID, TELEGRAM_API_HASH) as client:
        client.start(phone=TELEGRAM_PHONE)
        for ch in TELEGRAM_CHANNELS:
            print(f"  → @{ch}")
            try:
                msgs = client(GetHistoryRequest(peer=ch, limit=30, offset_id=0, offset_date=None,
                                                max_id=0, min_id=0, add_offset=0, hash=0))
                for m in msgs.messages:
                    iocs.extend(extract_iocs(m.message))
            except:
                pass
            time.sleep(0.3)
    print(f"[DEBUG] Extracted {len(set(iocs))} unique IOCs from Telegram")
    return list(set(iocs))


# ---- RSS ----
def fetch_rss_feeds():
    if not ENABLE_RSS:
        return []
    print("[INFO] Fetching from RSS...")
    iocs = []
    for url in RSS_FEEDS:
        print(f"  → {url}")
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:40]:
                text = f"{entry.get('title','')}\n{entry.get('summary','')}"
                iocs.extend(extract_iocs(text))
        except:
            pass
        time.sleep(0.2)
    print(f"[DEBUG] Extracted {len(set(iocs))} unique IOCs from RSS")
    return list(set(iocs))


# ---- MASTODON (public hashtag timelines) ----
def strip_html(s):
    # very simple HTML cleaner for Mastodon content fields
    return re.sub(r"<[^>]+>", " ", s or "")

def fetch_mastodon_feeds():
    if not ENABLE_MASTODON:
        return []
    print("[INFO] Fetching from Mastodon...")
    iocs = []
    for base, hashtag, limit in MASTODON_HASHTAGS:
        url = f"{base}/api/v1/timelines/tag/{hashtag}?limit={int(limit)}"
        print(f"  → {base} #{hashtag}")
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                for status in r.json():
                    content = strip_html(status.get("content", ""))
                    iocs.extend(extract_iocs(html.unescape(content)))
        except:
            pass
        time.sleep(0.3)
    print(f"[DEBUG] Extracted {len(set(iocs))} unique IOCs from Mastodon")
    return list(set(iocs))


# ---- GITHUB ----
def fetch_github_feeds():
    if not ENABLE_GITHUB:
        return []
    print("[INFO] Fetching from GitHub...")
    headers = {}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    iocs = []
    for repo in GITHUB_REPOS:
        owner, name = repo.split("/", 1)
        print(f"  → {repo}")
        # Issues
        try:
            issues = requests.get(
                f"https://api.github.com/repos/{owner}/{name}/issues?state=open&per_page=30",
                headers=headers, timeout=15).json()
            for it in issues:
                text = f"{it.get('title','')}\n{it.get('body','')}"
                iocs.extend(extract_iocs(text))
        except:
            pass
        # Releases
        try:
            rels = requests.get(
                f"https://api.github.com/repos/{owner}/{name}/releases?per_page=20",
                headers=headers, timeout=15).json()
            for rl in rels:
                text = f"{rl.get('name','')}\n{rl.get('body','')}"
                iocs.extend(extract_iocs(text))
        except:
            pass
        time.sleep(0.3)
    print(f"[DEBUG] Extracted {len(set(iocs))} unique IOCs from GitHub")
    return list(set(iocs))


# ---- YOUTUBE ----
def fetch_youtube_feeds():
    if not ENABLE_YOUTUBE or not YOUTUBE_API_KEY or not YOUTUBE_CHANNEL_IDS:
        return []
    print("[INFO] Fetching from YouTube...")
    iocs = []
    base = "https://www.googleapis.com/youtube/v3/search"
    for channel_id in YOUTUBE_CHANNEL_IDS:
        print(f"  → channel {channel_id}")
        try:
            params = {
                "part": "snippet",
                "channelId": channel_id,
                "order": "date",
                "maxResults": 20,
                "key": YOUTUBE_API_KEY,
            }
            r = requests.get(base, params=params, timeout=20)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("items", []):
                    sn = item.get("snippet", {})
                    text = f"{sn.get('title','')}\n{sn.get('description','')}"
                    iocs.extend(extract_iocs(text))
        except:
            pass
        time.sleep(0.3)
    print(f"[DEBUG] Extracted {len(set(iocs))} unique IOCs from YouTube")
    return list(set(iocs))


# ---- TWITTER/X via snscrape (no API key) ----
def fetch_twitter_feeds():
    if not ENABLE_TWITTER:
        return []
    print("[INFO] Fetching from Twitter (snscrape)...")
    iocs = []
    for q in TWITTER_QUERIES:
        print(f"  → query: {q}")
        try:
            # Example: snscrape --jsonl twitter-search "malware since:2025-07-01"
            proc = subprocess.run(
                [SNSCRAPE_PATH, "--jsonl", "twitter-search", q],
                capture_output=True, text=True, timeout=60
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines()[:200]:
                    try:
                        obj = json.loads(line)
                        content = obj.get("content", "")
                        iocs.extend(extract_iocs(content))
                    except:
                        pass
        except:
            pass
        time.sleep(0.3)
    print(f"[DEBUG] Extracted {len(set(iocs))} unique IOCs from Twitter")
    return list(set(iocs))


# ---- EXECUTION ----
if __name__ == "__main__":
    all_iocs = []

    if ENABLE_REDDIT:
        all_iocs += fetch_reddit_feeds()

    if ENABLE_TELEGRAM:
        all_iocs += fetch_telegram_feeds()

    all_iocs += fetch_rss_feeds()
    all_iocs += fetch_mastodon_feeds()
    all_iocs += fetch_github_feeds()
    all_iocs += fetch_youtube_feeds()
    all_iocs += fetch_twitter_feeds()

    # Dedup across sources
    all_iocs = list(set(all_iocs))
    print(f"[INFO] Total IOCs collected (pre-VT): {len(all_iocs)}")

    # Ingest per-source for clear tagging (kept same as your original per-source flow)
    if ENABLE_REDDIT:
        ingest_to_misp(fetch_reddit_feeds(), "Reddit")
    if ENABLE_TELEGRAM:
        ingest_to_misp(fetch_telegram_feeds(), "Telegram")
    if ENABLE_RSS:
        ingest_to_misp(fetch_rss_feeds(), "RSS")
    if ENABLE_MASTODON:
        ingest_to_misp(fetch_mastodon_feeds(), "Mastodon")
    if ENABLE_GITHUB:
        ingest_to_misp(fetch_github_feeds(), "GitHub")
    if ENABLE_YOUTUBE:
        ingest_to_misp(fetch_youtube_feeds(), "YouTube")
    if ENABLE_TWITTER:
        ingest_to_misp(fetch_twitter_feeds(), "Twitter")
