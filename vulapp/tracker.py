"""Upload/Download/Delete tracking system for monitoring user activity."""
import json
from datetime import datetime
from pathlib import Path
from flask import request

# Configuration
UPLOAD_TRACKER_FILE = Path('upload_tracker.json')
MAX_FILES_PER_IP = 50


def load_upload_tracker():
    """Load the upload tracker from file."""
    if UPLOAD_TRACKER_FILE.exists():
        try:
            with open(UPLOAD_TRACKER_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def save_upload_tracker(tracker):
    """Save the upload tracker to file."""
    try:
        with open(UPLOAD_TRACKER_FILE, 'w') as f:
            json.dump(tracker, f, indent=2)
    except IOError:
        pass


def get_client_ip():
    """Get the client's IP address, considering proxy headers."""
    if request.headers.get('X-Forwarded-For'):
        # Get the first IP in the chain (client IP)
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr


def get_upload_count(ip):
    """Get the number of files uploaded by this IP."""
    tracker = load_upload_tracker()
    return tracker.get(ip, {}).get('count', 0)


def increment_upload_count(ip, filename, file_size):
    """Increment the upload count for this IP and track the uploaded file."""
    tracker = load_upload_tracker()
    if ip not in tracker:
        tracker[ip] = {
            'count': 0,
            'first_upload': datetime.now().isoformat(),
            'files_uploaded': [],
            'files_deleted': [],
            'files_downloaded': []
        }

    # Ensure all lists exist (for backward compatibility)
    if 'files_uploaded' not in tracker[ip]:
        tracker[ip]['files_uploaded'] = []
    if 'files_deleted' not in tracker[ip]:
        tracker[ip]['files_deleted'] = []
    if 'files_downloaded' not in tracker[ip]:
        tracker[ip]['files_downloaded'] = []

    tracker[ip]['count'] += 1
    tracker[ip]['last_upload'] = datetime.now().isoformat()

    # Track the uploaded file with timestamp and size
    tracker[ip]['files_uploaded'].append({
        'filename': filename,
        'size': file_size,
        'timestamp': datetime.now().isoformat()
    })

    save_upload_tracker(tracker)


def track_file_deletion(ip, filename, file_size):
    """Track a file deletion for this IP."""
    tracker = load_upload_tracker()
    if ip not in tracker:
        tracker[ip] = {
            'count': 0,
            'first_upload': None,
            'files_uploaded': [],
            'files_deleted': [],
            'files_downloaded': []
        }

    # Ensure all lists exist
    if 'files_deleted' not in tracker[ip]:
        tracker[ip]['files_deleted'] = []

    # Track the deleted file with timestamp and size
    tracker[ip]['files_deleted'].append({
        'filename': filename,
        'size': file_size,
        'timestamp': datetime.now().isoformat()
    })

    save_upload_tracker(tracker)


def track_file_download(ip, filename, file_size):
    """Track a file download for this IP."""
    tracker = load_upload_tracker()
    if ip not in tracker:
        tracker[ip] = {
            'count': 0,
            'first_upload': None,
            'files_uploaded': [],
            'files_deleted': [],
            'files_downloaded': []
        }

    # Ensure all lists exist
    if 'files_downloaded' not in tracker[ip]:
        tracker[ip]['files_downloaded'] = []

    # Track the downloaded file with timestamp and size
    tracker[ip]['files_downloaded'].append({
        'filename': filename,
        'size': file_size,
        'timestamp': datetime.now().isoformat()
    })

    save_upload_tracker(tracker)
