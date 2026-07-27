from flask import Flask, jsonify, request

from app.models.threat import Threat

from app.services.threat_service import ThreatService
from app.services.auth_service import AuthService

from app.exceptions.validation_error import ValidationError

from app.auth.require_auth import require_auth
from app.auth.require_role import require_role


app = Flask(__name__)

service = ThreatService()
auth_service = AuthService()


@app.route("/")
def home():

    return "Threat System API is running!"


@app.route(
    "/register",
    methods=["POST"]
)
def register():

    try:

        data = request.get_json()

        auth_service.register(
            data["username"],
            data["password"]
        )

        return jsonify({
            "message":
            "User registered successfully"
        }), 201

    except ValidationError as e:

        return jsonify({
            "error": str(e)
        }), 400

    except Exception:

        return jsonify({
            "error":
            "Internal Server Error"
        }), 500


@app.route(
    "/login",
    methods=["POST"]
)
def login():

    try:

        data = request.get_json()

        token = auth_service.login(
            data["username"],
            data["password"]
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
            "error":
            "Internal Server Error"
        }), 500


@app.route(
    "/threats",
    methods=["POST"]
)
@require_auth
@require_role(
    "admin",
    "analyst"
)
def create_threat():

    try:

        data = request.get_json()

        threat = Threat(
            data["name"],
            data["threat_type"],
            data["impact"],
            data["solution"],
            data["location"],
            data["status"]
        )

        service.create(threat)

        return jsonify({
            "message":
            "Threat created successfully"
        }), 201

    except ValidationError as e:

        return jsonify({
            "error": str(e)
        }), 400

    except Exception:

        return jsonify({
            "error":
            "Internal Server Error"
        }), 500


@app.route(
    "/threats",
    methods=["GET"]
)
@require_auth
@require_role(
    "admin",
    "analyst",
    "viewer"
)
def get_threats():

    threats = service.get_all()

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

    return jsonify(results)


@app.route(
    "/threats/<int:threat_id>",
    methods=["GET"]
)
@require_auth
@require_role(
    "admin",
    "analyst",
    "viewer"
)
def get_threat(threat_id):

    threat = service.get_by_id(
        threat_id
    )

    if threat is None:

        return jsonify({
            "message":
            "Threat not found"
        }), 404

    return jsonify({

        "id": threat[0],
        "name": threat[1],
        "threat_type": threat[2],
        "impact": threat[3],
        "solution": threat[4],
        "location": threat[5],
        "status": threat[6]

    })


@app.route(
    "/threats/<int:threat_id>",
    methods=["PUT"]
)
@require_auth
@require_role(
    "admin",
    "analyst"
)
def update_threat(threat_id):

    try:

        data = request.get_json()

        service.update_status(
            threat_id,
            data["status"]
        )

        return jsonify({
            "message":
            "Threat updated successfully"
        })

    except ValidationError as e:

        return jsonify({
            "error": str(e)
        }), 400

    except Exception:

        return jsonify({
            "error":
            "Internal Server Error"
        }), 500


@app.route(
    "/threats/<int:threat_id>",
    methods=["DELETE"]
)
@require_auth
@require_role(
    "admin"
)
def delete_threat(threat_id):

    try:

        service.delete(
            threat_id
        )

        return jsonify({
            "message":
            "Threat deleted successfully"
        })

    except ValidationError as e:

        return jsonify({
            "error": str(e)
        }), 400

    except Exception:

        return jsonify({
            "error":
            "Internal Server Error"
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000
    )
