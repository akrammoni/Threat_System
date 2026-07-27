from app.models.threat import Threat
from app.services.threat_service import ThreatService


def main():

    threat = Threat(
        "Fake Banking Website",
        "Phishing",
        "High",
        "Block Domain",
        "Malaysia",
        "Active"
    )

    service = ThreatService()

    service.create(threat)

    print("Threat saved successfully!")


if __name__ == "__main__":
    main()
