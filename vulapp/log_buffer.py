"""Shared in-memory log buffer for the request log endpoint."""
from collections import deque

LOG_BUFFER = deque(maxlen=125_000)
