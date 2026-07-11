# TCPK mitmproxy capture addon. Loaded by Invoke-TcpkIntercept:
#   mitmdump -s tcpk_capture.py
# Writes one JSON object per completed response to $TCPK_INTERCEPT_OUT, which TCPK then
# parses into intercept.* findings. Read-only OBSERVATION: it never modifies a flow.
import json
import os

OUT = os.environ.get("TCPK_INTERCEPT_OUT", "tcpk-flows.jsonl")


def response(flow):
    try:
        req = flow.request
        resp = flow.response
        rec = {
            "method": req.method,
            "scheme": req.scheme,
            "host": req.host,
            "port": req.port,
            "path": req.path,
            "url": req.pretty_url,
            "req_headers": {k: v for k, v in req.headers.items()},
            "req_body": req.get_text(strict=False) or "",
            "status": resp.status_code if resp else None,
            "resp_headers": {k: v for k, v in resp.headers.items()} if resp else {},
            "resp_body": ((resp.get_text(strict=False) or "")[:4096]) if resp else "",
        }
        with open(OUT, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:
        pass
