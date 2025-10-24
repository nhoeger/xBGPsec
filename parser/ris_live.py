import json
from types import SimpleNamespace
from urllib.parse import quote
from websocket import create_connection

class RisLive:
    def __init__(self, params=None):
        params = params or {}
        host = params.get("host", "ris-live.ripe.net")
        self.client = params.get("client", "client")
        self.url = f"wss://{host}/v1/ws/?client={quote(self.client)}"

    def __iter__(self):
        # keep WS alive
        ws = create_connection(self.url, ping_interval=30, ping_timeout=10)
        # Subscribe to UPDATE stream (uppercase)
        sub = {"type": "ris_subscribe", "data": {"type": "UPDATE"}}
        ws.send(json.dumps(sub))
        try:
            while True:
                msg = ws.recv()  # JSON string
                yield SimpleNamespace(data=msg)
        finally:
            ws.close()