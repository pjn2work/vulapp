"""Admin routes - hidden, not registered with Flask-Smorest (no Swagger docs)."""
import subprocess
from flask import Blueprint, request, jsonify

admin_bp = Blueprint("admin", "admin", url_prefix="/admin")

AGENT_CONTAINER_NAME = "probely-agent"


@admin_bp.route('/addSnykAgent', methods=['POST'])
def add_agent():
    if request.headers.get('x-qa') != 'snyk':
        return jsonify({"error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()
    farcaster_api_url = data.get('farcaster_api_url', '').strip()

    if not token:
        return jsonify({"error": "Missing 'token' in request body"}), 400
    if not farcaster_api_url:
        return jsonify({"error": "Missing 'farcaster_api_url' in request body"}), 400
    if " " in token or " " in farcaster_api_url:
        return jsonify({"error": "Bad 'token' of 'api_url' values"}), 400

    # Stop and remove existing container (ignore errors if it doesn't exist)
    subprocess.run(
        ["docker", "stop", AGENT_CONTAINER_NAME],
        capture_output=True,
    )
    subprocess.run(
        ["docker", "rm", AGENT_CONTAINER_NAME],
        capture_output=True,
    )

    # Start new agent container
    result = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", AGENT_CONTAINER_NAME,
            "--cap-add", "NET_ADMIN",
            "-e", f"FARCASTER_AGENT_TOKEN={token}",
            "-e", f"FARCASTER_API_URL={farcaster_api_url}",
            "--device", "/dev/net/tun",
            "probely/farcaster-onprem-agent:v3",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return jsonify({
            "error": "Failed to start agent container",
            "details": result.stderr.strip(),
        }), 500

    return jsonify({
        "status": "ok",
        "container_id": result.stdout.strip(),
    }), 200


@admin_bp.route('/stopSnykAgent', methods=['POST'])
def stop_agent():
    if request.headers.get('x-qa') != 'snyk':
        return jsonify({"error": "Forbidden"}), 403

    stop = subprocess.run(["docker", "stop", AGENT_CONTAINER_NAME], capture_output=True, text=True)
    rm = subprocess.run(["docker", "rm", AGENT_CONTAINER_NAME], capture_output=True, text=True)

    if stop.returncode != 0 and rm.returncode != 0:
        return jsonify({
            "error": "Failed to stop agent container",
            "details": stop.stderr.strip(),
        }), 500

    return jsonify({"status": "ok"}), 200


@admin_bp.route('/getSnykAgentLogs', methods=['GET'])
def get_agent_logs():
    if request.headers.get('x-qa') != 'snyk':
        return jsonify({"error": "Forbidden"}), 403

    tail = request.args.get('tail', '')
    cmd = ["docker", "logs", AGENT_CONTAINER_NAME]
    if tail:
        cmd += ["--tail", tail]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return jsonify({
            "error": "Failed to get agent logs",
            "details": result.stderr.strip(),
        }), 500

    return jsonify({
        "logs": result.stdout + result.stderr,
    }), 200