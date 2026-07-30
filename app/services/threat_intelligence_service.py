import csv
import io
import os

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

        auth_key = os.getenv("URLHAUS_AUTH_KEY")

        if not auth_key:
            raise Exception("URLHAUS_AUTH_KEY is not configured")

        url = (
            "https://urlhaus-api.abuse.ch/v2/files/exports/"
            f"{auth_key}/recent.csv"
        )

        response = requests.get(
            url,
            timeout=30
        )

        response.raise_for_status()

        lines = [
            line for line in response.text.splitlines()
            if not line.startswith("#")
            and line.strip()
        ]

        reader = csv.DictReader(lines)

        results = []

        for item in reader:

            indicator = item.get("url")

            if not indicator:
                continue

            intelligence = ThreatIntelligence(
                indicator=indicator,
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
                last_seen=item.get(
                    "last_online"
                )
            )

            results.append(intelligence)

            if len(results) >= limit:
                break

        print("URLHAUS RECORDS PARSED:", len(results))

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
