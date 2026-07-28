class ThreatIntelligence:

    def __init__(
        self,
        indicator,
        indicator_type,
        threat_type,
        severity,
        source,
        description,
        first_seen=None,
        last_seen=None
    ):
        self.indicator = indicator
        self.indicator_type = indicator_type
        self.threat_type = threat_type
        self.severity = severity
        self.source = source
        self.description = description
        self.first_seen = first_seen
        self.last_seen = last_seen
