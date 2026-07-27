from app.repositories.threat_repository import ThreatRepository
from app.exceptions.validation_error import ValidationError


class ThreatService:

    def __init__(self):
        self.repository = ThreatRepository()


    def create(self, threat):

        if len(threat.name) < 5:
            raise ValidationError("Name too short")

        self.repository.create(threat)


    def get_all(self):
        return self.repository.get_all()


    def get_by_id(self, threat_id):
        return self.repository.get_by_id(threat_id)


    def update_status(self, threat_id, status):

        if status not in ["Active", "Resolved"]:
            raise ValidationError("Invalid status")

        self.repository.update_status(threat_id, status)


    def delete(self, threat_id):
        self.repository.delete(threat_id)
