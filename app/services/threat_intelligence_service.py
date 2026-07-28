import requests

from app.repositories.threat_intelligence_repository import (
    ThreatIntelligenceRepository
)


class ThreatIntelligenceService:

    def __init__(self):
        self.repository = ThreatIntelligenceRepository()

    def create(self, intelligence):

        self.repository.create(
            intelligence
        )

    def get_all(self):

        return self.repository.get_all()

    def fetch_urlhaus_data(self, limit=10):

        response = requests.get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        results = []

        for item in data.get("urls", [])[:limit]:

            results.append({
                "indicator": item.get("url"),
                "indicator_type": "url",
                "threat_type": item.get(
                    "threat",
                    "malicious_url"
                ),
                "severity": "high",
                "source": "URLhaus",
                "description": item.get(
                    "url_status"
                ),
                "first_seen": item.get(
                    "dateadded"
                ),
                "last_seen": None
            })

        return results
