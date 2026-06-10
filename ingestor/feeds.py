"""
SENTINEL — RSS Feed Ingestor
Fetches articles from configured feeds and passes new ones to the extractor.
"""

import json
import os
import hashlib
import yaml
import feedparser
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path
from extractor import extract_from_article

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
ACTORS_DIR = DATA_DIR / "actors"
SEEN_FILE = DATA_DIR / "seen_articles.json"
MENTIONS_FILE = DATA_DIR / "mentions.json"
ACTIVITY_FILE = DATA_DIR / "activity.json"
FEEDS_CONFIG = Path(__file__).parent / "config" / "feeds.yaml"

MAX_ARTICLES_PER_RUN = 20
LOOKBACK_HOURS = 6


def load_seen() -> set:
    if SEEN_FILE.exists():
        return set(json.loads(SEEN_FILE.read_text()))
    return set()


def save_seen(seen: set):
    SEEN_FILE.write_text(json.dumps(list(seen)))


def load_feeds_config() -> list:
    with open(FEEDS_CONFIG) as f:
        config = yaml.safe_load(f)
    return [f for f in config["feeds"] if f.get("format") != "csv"]


def load_actor_profiles() -> list:
    actors = []
    for f in ACTORS_DIR.glob("*.json"):
        try:
            actors.append(json.loads(f.read_text()))
        except Exception as e:
            print(f"Error loading {f}: {e}")
    return actors


def load_mentions() -> dict:
    if MENTIONS_FILE.exists():
        return json.loads(MENTIONS_FILE.read_text())
    return {"last_updated": "", "mentions": []}


def save_mentions(data: dict):
    data["last_updated"] = datetime.utcnow().isoformat() + "Z"
    MENTIONS_FILE.write_text(json.dumps(data, indent=2))


def load_activity() -> dict:
    if ACTIVITY_FILE.exists():
        return json.loads(ACTIVITY_FILE.read_text())
    return {"last_updated": "", "top_actors": []}


def save_activity(data: dict):
    data["last_updated"] = datetime.utcnow().isoformat() + "Z"
    ACTIVITY_FILE.write_text(json.dumps(data, indent=2))


def update_actor_mention_count(actor_id: str, mentions_data: dict):
    """Increment 30-day mention count for an actor."""
    actor_file = ACTORS_DIR / f"{actor_id}.json"
    if not actor_file.exists():
        return
    
    actor = json.loads(actor_file.read_text())
    
    # Count mentions in last 30 days from the mentions feed
    cutoff = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")
    count = sum(
        1 for m in mentions_data.get("mentions", [])
        if m.get("actor_id") == actor_id and m.get("date", "") >= cutoff
    )
    
    actor["mention_count_30d"] = count
    actor_file.write_text(json.dumps(actor, indent=2))


def article_url_hash(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()


def fetch_feed(feed_config: dict) -> list:
    """Fetch and parse an RSS feed, return list of recent articles."""
    articles = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    
    try:
        parsed = feedparser.parse(feed_config["url"])
        for entry in parsed.entries[:15]:
            pub_date = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                pub_date = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            
            # Include if recent or no date available
            if pub_date and pub_date < cutoff:
                continue
            
            articles.append({
                "title": getattr(entry, "title", ""),
                "url": getattr(entry, "link", ""),
                "summary": getattr(entry, "summary", "")[:1000],
                "published": pub_date.isoformat() if pub_date else "",
                "source_name": feed_config["name"]
            })
    except Exception as e:
        print(f"Error fetching {feed_config['name']}: {e}")
    
    return articles


def infer_actor_id(actor_name: str, actor_profiles: list) -> str | None:
    """Map actor name to profile ID."""
    name_lower = actor_name.lower()
    for actor in actor_profiles:
        if actor["name"].lower() == name_lower:
            return actor["id"]
        if any(alias.lower() == name_lower for alias in actor.get("aliases", [])):
            return actor["id"]
    return None


def run_ingestor():
    print(f"SENTINEL ingestor starting — {datetime.utcnow().isoformat()}Z")
    
    seen = load_seen()
    feeds_config = load_feeds_config()
    actor_profiles = load_actor_profiles()
    mentions_data = load_mentions()
    activity_data = load_activity()
    
    new_articles = []
    
    for feed in feeds_config:
        articles = fetch_feed(feed)
        for article in articles:
            url_hash = article_url_hash(article["url"])
            if url_hash not in seen and article["url"]:
                new_articles.append(article)
                seen.add(url_hash)
    
    print(f"Found {len(new_articles)} new articles")
    new_articles = new_articles[:MAX_ARTICLES_PER_RUN]
    
    new_mentions = []
    
    for article in new_articles:
        print(f"  Processing: {article['title'][:60]}...")
        
        extraction = extract_from_article(
            article["title"],
            article["summary"],
            article["url"]
        )
        
        if extraction.get("relevance_score", 0) < 20:
            continue
        
        for actor_name in extraction.get("named_actors", []):
            actor_id = infer_actor_id(actor_name, actor_profiles)
            
            new_mentions.append({
                "date": datetime.utcnow().strftime("%Y-%m-%d"),
                "actor_id": actor_id or actor_name.lower().replace(" ", "-"),
                "actor_name": actor_name,
                "source": article["source_name"],
                "url": article["url"],
                "title": article["title"],
                "context": "Named threat actor",
                "confidence": extraction.get("confidence", "medium"),
                "ttps_observed": extraction.get("ttps", []),
                "summary": extraction.get("summary", "")
            })
    
    if new_mentions:
        # Prepend new mentions, keep last 200
        mentions_data["mentions"] = new_mentions + mentions_data.get("mentions", [])
        mentions_data["mentions"] = mentions_data["mentions"][:200]
        save_mentions(mentions_data)
        print(f"Added {len(new_mentions)} new mentions")
        
        # Update actor mention counts
        mentioned_actor_ids = set(m["actor_id"] for m in new_mentions if m["actor_id"])
        for actor_id in mentioned_actor_ids:
            update_actor_mention_count(actor_id, mentions_data)
        
        # Refresh activity.json
        updated_actors = []
        for actor in activity_data.get("top_actors", []):
            profile_file = ACTORS_DIR / f"{actor['id']}.json"
            if profile_file.exists():
                profile = json.loads(profile_file.read_text())
                actor["mention_count_30d"] = profile.get("mention_count_30d", actor["mention_count_30d"])
                actor["activity_score"] = profile.get("activity_score", actor["activity_score"])
            updated_actors.append(actor)
        
        activity_data["top_actors"] = sorted(updated_actors, key=lambda x: x["activity_score"], reverse=True)
        save_activity(activity_data)
    
    save_seen(seen)
    print(f"Ingestor complete — {len(new_articles)} articles processed, {len(new_mentions)} mentions added")


if __name__ == "__main__":
    run_ingestor()
