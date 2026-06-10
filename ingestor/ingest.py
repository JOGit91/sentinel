#!/usr/bin/env python3
"""
SENTINEL Ingestor
Fetches RSS feeds, extracts threat actor mentions and TTPs via Claude API,
updates data/actors/*.json and data/mentions.json
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import feedparser
import requests
import yaml

# ── CONFIG ──
REPO_ROOT   = Path(__file__).parent.parent
DATA_DIR    = REPO_ROOT / "docs" / "data"
ACTORS_DIR  = DATA_DIR / "actors"
FEEDS_CFG   = Path(__file__).parent / "config" / "feeds.yaml"
MENTIONS_F  = DATA_DIR / "mentions.json"
ACTIVITY_F  = DATA_DIR / "activity.json"

API_URL     = "https://api.anthropic.com/v1/messages"
API_KEY     = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL       = "claude-sonnet-4-20250514"
MAX_TOKENS  = 1000

LOOKBACK_HOURS = 6      # Only process articles published in last N hours
MAX_MENTIONS   = 200    # Rolling window for mentions.json


def log(msg):
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)


# ── LOAD KNOWN ACTORS ──
def load_actors():
    actors = {}
    for path in ACTORS_DIR.glob("*.json"):
        with open(path) as f:
            data = json.load(f)
            actors[data["id"]] = data
    return actors


def save_actor(actor):
    path = ACTORS_DIR / f"{actor['id']}.json"
    with open(path, "w") as f:
        json.dump(actor, f, indent=2)


# ── LOAD / SAVE MENTIONS ──
def load_mentions():
    if MENTIONS_F.exists():
        with open(MENTIONS_F) as f:
            return json.load(f)
    return {"last_updated": "", "mentions": []}


def save_mentions(data):
    data["last_updated"] = datetime.now(timezone.utc).isoformat()
    with open(MENTIONS_F, "w") as f:
        json.dump(data, f, indent=2)


# ── LOAD / SAVE ACTIVITY ──
def load_activity():
    if ACTIVITY_F.exists():
        with open(ACTIVITY_F) as f:
            return json.load(f)
    return {"last_updated": "", "top_actors": []}


def save_activity(actors):
    top = sorted(actors.values(), key=lambda a: a.get("activity_score", 0), reverse=True)
    data = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "top_actors": [
            {
                "id": a["id"],
                "name": a["name"],
                "activity_score": a.get("activity_score", 0),
                "mention_count": a.get("mention_count", 0),
                "type": a.get("type", "unknown"),
            }
            for a in top
        ]
    }
    with open(ACTIVITY_F, "w") as f:
        json.dump(data, f, indent=2)


# ── RSS FETCHING ──
def fetch_feeds():
    with open(FEEDS_CFG) as f:
        cfg = yaml.safe_load(f)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    articles = []

    for feed_cfg in cfg["feeds"]:
        try:
            log(f"Fetching {feed_cfg['name']}...")
            feed = feedparser.parse(feed_cfg["url"])
            for entry in feed.entries:
                # Parse published date
                pub = None
                if hasattr(entry, "published_parsed") and entry.published_parsed:
                    pub = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
                elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
                    pub = datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc)

                if pub and pub < cutoff:
                    continue  # Too old

                articles.append({
                    "title": entry.get("title", ""),
                    "url": entry.get("link", ""),
                    "summary": entry.get("summary", "")[:1000],
                    "source": feed_cfg["name"],
                    "date": pub.isoformat() if pub else datetime.now(timezone.utc).isoformat(),
                })
        except Exception as e:
            log(f"  Error fetching {feed_cfg['name']}: {e}")

    log(f"Found {len(articles)} new articles across {len(cfg['feeds'])} feeds")
    return articles


# ── CLAUDE API EXTRACTION ──
def extract_intel(article, known_actors):
    """
    Calls Claude API to extract threat actor mentions and TTPs from an article.
    Returns structured dict or None if no relevant intel found.
    """
    if not API_KEY:
        log("  No API key — skipping extraction")
        return None

    actor_names = [a["name"] for a in known_actors.values()]
    actor_aliases = []
    for a in known_actors.values():
        actor_aliases.extend(a.get("aliases", []))

    prompt = f"""You are a threat intelligence analyst. Analyze this article and extract structured intel.

Article Title: {article['title']}
Source: {article['source']}
Content: {article['summary']}

Known threat actors to watch for: {', '.join(actor_names + actor_aliases)}

Return ONLY a JSON object (no markdown, no preamble) with this structure:
{{
  "relevant": true/false,
  "actors_mentioned": [
    {{
      "name": "exact name as mentioned",
      "matched_id": "id from known actors list or null",
      "context": "brief 1-sentence context of how mentioned"
    }}
  ],
  "ttps_observed": ["T1190", "T1078"],
  "iocs": [
    {{"type": "ip/domain/hash/url", "value": "the IOC value"}}
  ],
  "malware_mentioned": ["name1", "name2"],
  "targeted_sectors": ["sector1"],
  "summary": "1-2 sentence summary of threat intel in this article"
}}

Only set relevant=true if the article contains actionable threat intelligence about a specific threat actor, campaign, or attack technique. News articles without specific TTPs or actor attribution should be relevant=false."""

    try:
        resp = requests.post(
            API_URL,
            headers={
                "x-api-key": API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": MODEL,
                "max_tokens": MAX_TOKENS,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        raw = resp.json()["content"][0]["text"].strip()
        # Strip any accidental markdown fences
        raw = re.sub(r"^```json\s*|\s*```$", "", raw, flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception as e:
        log(f"  API extraction error: {e}")
        return None


# ── ACTOR ID RESOLUTION ──
def resolve_actor(name, actors):
    """Match an extracted actor name to a known actor ID."""
    name_lower = name.lower()
    for actor in actors.values():
        if actor["name"].lower() == name_lower:
            return actor["id"]
        for alias in actor.get("aliases", []):
            if alias.lower() == name_lower:
                return actor["id"]
    return None


# ── MAIN PIPELINE ──
def run():
    log("── SENTINEL INGESTOR ──")

    actors   = load_actors()
    mentions = load_mentions()
    articles = fetch_feeds()

    new_mention_count = 0

    for article in articles:
        log(f"Processing: {article['title'][:70]}...")
        intel = extract_intel(article, actors)

        if not intel or not intel.get("relevant"):
            continue

        # Process each mentioned actor
        for mention in intel.get("actors_mentioned", []):
            actor_id = mention.get("matched_id") or resolve_actor(mention["name"], actors)

            if actor_id and actor_id in actors:
                actor = actors[actor_id]

                # Increment mention count
                actor["mention_count"] = actor.get("mention_count", 0) + 1
                actor["last_seen"] = datetime.now(timezone.utc).strftime("%Y-%m")

                # Add new IOCs (deduplicated)
                existing_iocs = {i["value"] for i in actor.get("iocs", [])}
                for ioc in intel.get("iocs", []):
                    if ioc["value"] not in existing_iocs:
                        actor.setdefault("iocs", []).append({
                            "type": ioc["type"],
                            "value": ioc["value"],
                            "source": article["url"],
                            "date": article["date"],
                        })
                        existing_iocs.add(ioc["value"])

                # Nudge activity score based on recency
                actor["activity_score"] = min(100, actor.get("activity_score", 50) + 1)

                save_actor(actor)

            # Add to mentions feed
            mentions["mentions"].insert(0, {
                "actor_id": actor_id or "unknown",
                "actor_name": mention["name"],
                "title": article["title"],
                "url": article["url"],
                "source": article["source"],
                "date": article["date"],
                "context": mention.get("context", ""),
            })
            new_mention_count += 1

        # Small delay to respect rate limits
        time.sleep(0.5)

    # Trim mentions to rolling window
    mentions["mentions"] = mentions["mentions"][:MAX_MENTIONS]

    save_mentions(mentions)
    save_activity(actors)

    log(f"── Done. Processed {len(articles)} articles, added {new_mention_count} mentions ──")


if __name__ == "__main__":
    run()
