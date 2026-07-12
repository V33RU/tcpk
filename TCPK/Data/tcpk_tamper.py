# TCPK mitmproxy TAMPER addon. Applies literal find/replace rules from $TCPK_TAMPER_RULES
# (a JSON list of {find, replace, where}) to LIVE flows -- the pentest "modify a request /
# response in flight" capability, to probe server-side authorization and injection handling.
# GATED by the cmdlet (Enable-TcpkExploit + -ConfirmActive). Each change is logged to
# $TCPK_TAMPER_OUT so TCPK can report exactly what was altered.
import json
import os

RULES = []
try:
    RULES = json.loads(os.environ.get("TCPK_TAMPER_RULES", "[]"))
except Exception:
    RULES = []
OUT = os.environ.get("TCPK_TAMPER_OUT", "")


def _log(msg):
    if not OUT:
        return
    try:
        with open(OUT, "a", encoding="utf-8") as fh:
            fh.write(msg + "\n")
    except Exception:
        pass


def _apply(text, where):
    changed = False
    for r in RULES:
        w = r.get("where", "both")
        if w not in ("both", where):
            continue
        find = r.get("find", "")
        repl = r.get("replace", "")
        if find and find in text:
            text = text.replace(find, repl)
            changed = True
            _log("TCPKTAMPER %s: %r -> %r" % (where, find, repl))
    return text, changed


def request(flow):
    try:
        body = flow.request.get_text(strict=False) or ""
        new, changed = _apply(body, "req")
        if changed:
            flow.request.text = new
    except Exception:
        pass


def response(flow):
    try:
        body = flow.response.get_text(strict=False) or ""
        new, changed = _apply(body, "resp")
        if changed:
            flow.response.text = new
    except Exception:
        pass
