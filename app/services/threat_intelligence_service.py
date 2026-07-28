import requests

from app.models.threat_intelligence import ThreatIntelligence
from app.repositories.threat_intelligence_repository import (
    ThreatIntelligenceRepository
)


class ThreatIntelligenceService:

    def __init__(self):
        self.repository = ThreatIntelligenceRepository()

    def create(self, intelligence):
        self.repository.create(intelligence)

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

            intelligence = ThreatIntelligence(
                indicator=item.get("url"),
                indicator_type="url",
                threat_type=item.get(
                    "threat",
                    "malicious_url"
                ),
                severity="high",
                source="URLhaus",
                description=item.get(
                    "url_status"
                ),
                first_seen=item.get(
                    "dateadded"
                ),
                last_seen=None
            )

            results.append(intelligence)

        return results

    def sync_urlhaus(self, limit=10):

        intelligence_items = self.fetch_urlhaus_data(
            limit
        )

        imported = 0

        for intelligence in intelligence_items:

            self.repository.create(
                intelligence
            )

            imported += 1

        return imported
