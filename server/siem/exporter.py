import json
import socket

from server.config import settings


def send_syslog(message: dict):
    if not settings.siem_enabled:
        return
    payload = json.dumps(message).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload, (settings.syslog_host, settings.syslog_port))
    sock.close()
