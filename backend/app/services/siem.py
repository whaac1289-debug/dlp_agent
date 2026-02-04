import json
import socket

from app.core.config import settings


def send_syslog(message: dict):
    payload = json.dumps(message).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload, (settings.syslog_host, settings.syslog_port))
    sock.close()
