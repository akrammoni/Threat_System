from flask import Flask, request, jsonify, render_template

from app.auth.require_auth import require_auth
from app.auth.require_role import require_role

from app.models.threat import Threat
from app.models.threat_intelligence import ThreatIntelligence

from app.services.threat_service import ThreatService
from app.services.auth_service import AuthService
from app.services.threat_intelligence_service import (
    ThreatIntelligenceService
)

from app.exceptions.validation_error import ValidationError


app = Flask(__name__)
@app.route("/ui")
def ui():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# =========================
# SERVICES
# =========================

threat_service = ThreatService()
auth_service = AuthService()
threat_intelligence_service = ThreatIntelligenceService()


# =========================
# HEALTH CHECK
# =========================

@app.route("/", methods=["GET"])
def home():

    return "Threat System API is running!", 200


# =========================
# AUTHENTICATION
# =========================

@app.route("/register", methods=["POST"])
def register():

    try:

        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        auth_service.register(
            username,
            password
        )

        return jsonify({
            "message": "User registered successfully"
        }), 201

    except ValidationError as e:

        return jsonify({
            "error": str(e)
        }), 400

    except Exception:

        return jsonify({
            "error": "Internal Server Error"
        }), 500


@app.route("/login", methods=["POST"])
def login():

    try:

        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        token = auth_service.login(
            username,
            password
        )

        return jsonify({
            "access_token": token
        }), 200

    except ValidationError as e:

        return jsonify({
            "error": str(e)
        }), 401

    except Exception:

        return jsonify({
            "error": "Internal Server Error"
        }), 500


# =========================
# THREATS
# =========================

@app.route("/threats", methods=["GET"])
@require_auth
@require_role(
    "admin",
    "analyst",
    "viewer"
)
def get_threats():

    try:

        threats = threat_service.get_all()

        results = []

        for threat in threats:

            results.append({
                "id": threat[0],
                "name": threat[1],
                "threat_type": threat[2],
                "impact": threat[3],
                "solution": threat[4],
                "location": threat[5],
                "status": threat[6]
            })

        return jsonify(results), 200

    except Exception:

        return jsonify({
            "error": "Internal Server Error"
        }), 500


@app.route("/threats", methods=["POST"])
@require_auth
@require_role(
    "admin",
    "analyst"
)
def create_threat():

    try:

        data = request.get_json()

        threat = Threat(
            name=data["name"],
            threat_type=data["threat_type"],
            impact=data.get("impact"),
            solution=data.get("solution"),
            location=data.get("location"),
            status=data.get("status")
        )

        threat_service.create(threat)

        return jsonify({
            "message": "Threat created successfully"
        }), 201

    except ValidationError as e:

        return jsonify({
            "error": str(e)
        }), 400

    except Exception:

        return jsonify({
            "error": "Internal Server Error"
        }), 500


# =========================
# THREAT INTELLIGENCE
# =========================

@app.route(
    "/threat-intelligence",
    methods=["POST"]
)
@require_auth
@require_role(
    "admin",
    "analyst"
)
def create_threat_intelligence():

    try:

        data = request.get_json()

        intelligence = ThreatIntelligence(
            indicator=data["indicator"],
            indicator_type=data["indicator_type"],
            threat_type=data["threat_type"],
            severity=data["severity"],
            source=data["source"],
            description=data.get("description"),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen")
        )

        threat_intelligence_service.create(
            intelligence
        )

        return jsonify({
            "message":
            "Threat intelligence created successfully"
        }), 201

    except KeyError as e:

        return jsonify({
            "error":
            f"Missing required field: {e.args[0]}"
        }), 400

    except Exception:

        return jsonify({
            "error":
            "Internal Server Error"
        }), 500


@app.route(
    "/threat-intelligence",
    methods=["GET"]
)
@require_auth
@require_role(
    "admin",
    "analyst",
    "viewer"
)
def get_threat_intelligence():

    try:

        intelligence = (
            threat_intelligence_service
            .get_all()
        )

        results = []

        for item in intelligence:

            results.append({
                "id": item[0],
                "indicator": item[1],
                "indicator_type": item[2],
                "threat_type": item[3],
                "severity": item[4],
                "source": item[5],
                "description": item[6],
                "first_seen": item[7],
                "last_seen": item[8],
                "created_at": item[9]
            })

        return jsonify(results), 200

    except Exception:

        return jsonify({
            "error":
            "Internal Server Error"
        }), 500


# =========================
# URLHAUS THREAT INTELLIGENCE SYNC
# =========================

@app.route(
    "/threat-intelligence/sync",
    methods=["POST"]
)
@require_auth
@require_role(
    "admin",
    "analyst"
)
def sync_threat_intelligence():

    try:

        imported = (
            threat_intelligence_service
            .sync_urlhaus(
                limit=10
            )
        )

        return jsonify({
            "message":
            "Threat intelligence synced successfully",
            "source": "URLhaus",
            "imported": imported
        }), 200

    except Exception as e:

        return jsonify({
            "error":
            "Threat intelligence sync failed",
            "details": str(e)
        }), 500


# =========================
# RUN APPLICATION
# =========================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )
