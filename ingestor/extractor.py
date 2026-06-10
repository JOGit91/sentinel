"""
SENTINEL — LLM Extraction Pipeline
Calls Claude API to extract threat actor mentions, TTPs, IOCs from articles.
"""

import json
import os
import re
from datetime import datetime
import anthropic

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

KNOWN_ACTORS = [
    "Qilin", "Agenda", "The Gentlemen", "ShinyHunters", "UNC6040", "UNC6240", "SLSH",
    "TeamPCP", "DeadCatx3", "PCPcat", "ShellForce", "CipherForce",
    "UNC6692", "Storm-1811", "Salt Typhoon", "GhostEmperor", "FamousSparrow",
    "Volt Typhoon", "Scattered Spider", "UNC3944", "LAPSUS$", "Akira", "LockBit",
    "BlackCat", "ALPHV", "RansomHub", "Cl0p", "TA505", "FIN7", "Lazarus Group",
    "APT28", "APT29", "Cozy Bear", "Fancy Bear"
]

SYSTEM_PROMPT = """You are a threat intelligence extraction system. 
Given article text, extract structured threat intelligence data.

Return ONLY valid JSON, no markdown, no explanation, no preamble.

Schema:
{
  "named_actors": ["actor names explicitly mentioned"],
  "ttps": ["T1234", "T1234.001"],
  "iocs": {
    "ips": [],
    "domains": [],
    "hashes": [],
    "tools": []
  },
  "malware_families": [],
  "targeted_sectors": [],
  "targeted_regions": [],
  "summary": "1-2 sentence summary of threat activity described",
  "confidence": "high|medium|low",
  "relevance_score": 0-100
}

Known actors to watch for: """ + ", ".join(KNOWN_ACTORS)


def extract_from_article(title: str, content: str, url: str) -> dict:
    """Extract TI from article text using Claude API."""
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Title: {title}\n\nURL: {url}\n\nContent:\n{content[:4000]}"
            }]
        )

        raw = response.content[0].text.strip()
        # Strip any accidental markdown fences
        raw = re.sub(r'^```json\s*', '', raw)
        raw = re.sub(r'\s*```$', '', raw)

        data = json.loads(raw)
        data["source_url"] = url
        data["source_title"] = title
        data["extracted_at"] = datetime.utcnow().isoformat() + "Z"
        return data

    except Exception as e:
        print(f"Extraction error for {url}: {e}")
        return {
            "named_actors": [],
            "ttps": [],
            "iocs": {"ips": [], "domains": [], "hashes": [], "tools": []},
            "malware_families": [],
            "targeted_sectors": [],
            "targeted_regions": [],
            "summary": "",
            "confidence": "low",
            "relevance_score": 0,
            "source_url": url,
            "source_title": title,
            "extracted_at": datetime.utcnow().isoformat() + "Z",
            "error": str(e)
        }


def attribute_actor(observables: dict, actor_profiles: list) -> list:
    """
    Given observables (ttps, sectors, malware, iocs), score each known actor
    and return ranked candidates.
    
    observables = {
        "ttps": ["T1190", "T1078"],
        "sectors": ["Healthcare"],
        "malware": ["SystemBC"],
        "ioc_hints": ["Mullvad VPN", "NETLOGON"]
    }
    """
    results = []

    for actor in actor_profiles:
        score = 0
        matches = []

        # TTP matching
        actor_ttp_ids = [t["technique_id"].lower() for t in actor.get("ttps", [])]
        for ttp in observables.get("ttps", []):
            if ttp.lower() in actor_ttp_ids:
                score += 25
                matches.append(f"TTP: {ttp}")

        # Sector matching
        actor_sectors = [s.lower() for s in actor.get("targeted_sectors", [])]
        for sector in observables.get("sectors", []):
            if any(sector.lower() in s or s in sector.lower() for s in actor_sectors):
                score += 20
                matches.append(f"Sector: {sector}")

        # Malware matching
        actor_malware = [m.lower() for m in actor.get("malware_families", [])]
        for malware in observables.get("malware", []):
            if any(malware.lower() in m or m in malware.lower() for m in actor_malware):
                score += 30
                matches.append(f"Malware: {malware}")

        # IOC hint matching against notable techniques and detection opportunities
        notable = " ".join(actor.get("notable_techniques", [])).lower()
        detect = " ".join(actor.get("detection_opportunities", [])).lower()
        combined = notable + " " + detect
        for hint in observables.get("ioc_hints", []):
            if len(hint) > 3 and hint.lower() in combined:
                score += 20
                matches.append(f"IOC hint: {hint}")

        # Weight by activity score
        if score > 0:
            score += actor.get("activity_score", 0) * 0.1

        if score > 0:
            results.append({
                "actor_id": actor["id"],
                "actor_name": actor["name"],
                "score": round(score),
                "matches": list(set(matches)),
                "activity_score": actor.get("activity_score", 0)
            })

    return sorted(results, key=lambda x: x["score"], reverse=True)[:5]


if __name__ == "__main__":
    # Test extraction
    test_title = "Qilin Ransomware Targets Healthcare Organizations via VPN Vulnerabilities"
    test_content = "The Qilin ransomware group, also tracked as Agenda, has been observed targeting healthcare organizations by exploiting public-facing VPN appliances. The group uses PowerShell for execution and PsExec for lateral movement before deploying their Rust-based encryptor."
    result = extract_from_article(test_title, test_content, "https://example.com/test")
    print(json.dumps(result, indent=2))
