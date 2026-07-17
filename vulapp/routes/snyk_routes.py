"""Admin routes - hidden, not registered with Flask-Smorest (no Swagger docs)."""
import subprocess
from flask import Blueprint, request, jsonify

snyk_bp = Blueprint("snyk", "snyk", url_prefix="/snyk")

AGENT_CONTAINER_NAME = "probely-agent"
_last_start_cmd = ""


@snyk_bp.route('/agent/start', methods=['POST'])
def add_agent():
    global _last_start_cmd
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
    try:
        subprocess.run(["docker", "stop", AGENT_CONTAINER_NAME], capture_output=True)
        subprocess.run(["docker", "rm", AGENT_CONTAINER_NAME], capture_output=True)
    except Exception as e:
        return jsonify({"error": "Failed to stop existing agent container", "details": str(e)}), 500

    # Start new agent container
    _last_start_cmd = (
        f"docker run -d --name {AGENT_CONTAINER_NAME} --cap-add NET_ADMIN"
        f" -e FARCASTER_AGENT_TOKEN={token}"
        f" -e FARCASTER_API_URL={farcaster_api_url}"
        #f" -e FARCASTER_FORCE_TCP=1"
        f" --device /dev/net/tun probely/farcaster-onprem-agent:v3"
    )
    try:
        result = subprocess.run(
            [
                "docker", "run", "-d",
                "--name", AGENT_CONTAINER_NAME,
                "--cap-add", "NET_ADMIN",
                "-e", f"FARCASTER_AGENT_TOKEN={token}",
                "-e", f"FARCASTER_API_URL={farcaster_api_url}",
                #"-e", f"FARCASTER_FORCE_TCP=1",
                "--device", "/dev/net/tun",
                "probely/farcaster-onprem-agent:v3",
            ],
            capture_output=True,
            text=True,
        )
    except Exception as e:
        return jsonify({"error": "Failed to start agent container", "details": str(e)}), 500

    if result.returncode != 0:
        return jsonify({
            "error": "Failed to start agent container",
            "details": "\n".join(result.stderr.strip().splitlines()[-4:]),
        }), 500

    return jsonify({
        "status": "ok",
        "container_id": result.stdout.strip(),
    }), 200


@snyk_bp.route('/agent/stop', methods=['POST'])
def stop_agent():
    if request.headers.get('x-qa') != 'snyk':
        return jsonify({"error": "Forbidden"}), 403

    try:
        stop = subprocess.run(["docker", "stop", AGENT_CONTAINER_NAME], capture_output=True, text=True)
        rm = subprocess.run(["docker", "rm", AGENT_CONTAINER_NAME], capture_output=True, text=True)
    except Exception as e:
        return jsonify({"error": "Failed to stop agent container", "details": str(e)}), 500

    if stop.returncode != 0 and rm.returncode != 0:
        return jsonify({
            "error": "Failed to stop agent container",
            "details": stop.stderr.strip(),
        }), 500

    return jsonify({"status": "ok"}), 200


@snyk_bp.route('/agent/logs', methods=['GET'])
def get_agent_logs():
    if request.headers.get('x-qa') != 'snyk':
        return jsonify({"error": "Forbidden"}), 403

    tail = request.args.get('tail', '')
    cmd = ["docker", "logs", AGENT_CONTAINER_NAME]
    if tail:
        cmd += ["--tail", tail]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        return jsonify({"error": "Failed to get agent logs", "details": str(e)}), 500

    if result.returncode != 0:
        return jsonify({
            "error": "Failed to get agent logs",
            "details": result.stderr.strip(),
        }), 500

    logs = (
        "\n--- start command ---" +
        f"\n{_last_start_cmd}" +
        "\n-- stdout --\n" +
        "\n".join(result.stdout.strip().splitlines()) +
        "\n-- stderr --\n" +
        "\n".join(result.stderr.strip().splitlines())
    )

    return jsonify({"logs": logs}), 200