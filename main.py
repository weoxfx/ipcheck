import os
import hashlib
import hmac
import time
import logging
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger(__name__)

app    = Flask(__name__)
SECRET = os.environ.get("SECRET", "xeo_fp_secret_change_sureiwillchangeyoufreakme")

# In-memory store: token -> {"ip_hash": ..., "user_id": ..., "ts": ...}
results = {}

# ── Helpers ────────────────────────────────────────────────────────────────────

def verify_token(token: str, max_age: int = 3600):
    """
    Returns user_id if token valid and not expired, else None.
    Token format: {uid}_{timestamp}_{hmac16hex}
    
    This version supports both:
    1. Standard timestamps (seconds since epoch)
    2. Windowed timestamps (rounded to 1800s)
    """
    try:
        parts = token.strip().rsplit("_", 2)
        if len(parts) != 3:
            log.warning(f"Bad token format: {token[:40]}")
            return None

        uid_str, ts_str, sig = parts
        uid = int(uid_str)
        ts  = int(ts_str)

        # Check if it's a windowed timestamp (usually divisible by 1800)
        # or a raw second timestamp.
        now = time.time()
        
        # If the timestamp is very small (e.g. < 10^9), it's likely not a modern epoch.
        # But here they are standard epochs.
        
        age = now - ts
        log.info(f"Token age: {age:.1f}s for uid={uid}")

        # Verification logic: 
        # Windowed tokens (rounded to 1800) can appear to be up to 1800s "old" immediately
        # or even slightly in the "future" if clocks aren't synced.
        # We allow a generous 1 hour (3600s) window and 60s future buffer.
        if age > max_age:
            log.warning(f"Token expired: age={age:.1f}s > max={max_age}s")
            return None
        if age < -60: 
            log.warning(f"Token from future: age={age:.1f}s")
            return None

        raw      = f"{uid}:{ts}"
        expected = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:16]

        if not hmac.compare_digest(expected, sig):
            log.warning(f"Bad signature for uid={uid}")
            return None

        return uid
    except Exception as e:
        log.error(f"Token verify error: {e}")
        return None

def hash_ip(ip: str) -> str:
    return hashlib.sha256((SECRET + ip).encode()).hexdigest()

def get_real_ip() -> str:
    for header in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"):
        val = request.headers.get(header, "").split(",")[0].strip()
        if val:
            return val
    return request.remote_addr or "unknown"

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/verify")
def verify():
    token = request.args.get("token", "").strip()
    log.info(f"Verify request: token={token[:40]}... ip={get_real_ip()}")

    # We allow 1 hour for the link to be clicked
    user_id = verify_token(token, max_age=3600)

    if not user_id:
        log.warning(f"Invalid/expired token: {token[:40]}")
        return _expired_page(), 400

    ip      = get_real_ip()
    ip_hash = hash_ip(ip)

    results[token] = {
        "ip_hash": ip_hash,
        "user_id": user_id,
        "ts":      time.time()
    }
    log.info(f"Verified uid={user_id} stored")

    return _success_page()


@app.route("/result")
def result():
    token = request.args.get("token", "").strip()

    now     = time.time()
    expired = [k for k, v in results.items() if now - v["ts"] > 900]
    for k in expired:
        results.pop(k, None)

    if token not in results:
        return jsonify({"ready": False})

    data = results.pop(token)
    return jsonify({
        "ready":   True,
        "ip_hash": data["ip_hash"],
        "user_id": data["user_id"]
    })


@app.route("/ping")
def ping():
    return jsonify({"status": "ok", "time": int(time.time())})


# ── Page templates ─────────────────────────────────────────────────────────────

def _success_page():
    return """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Verified!</title>
  <script src="https://telegram.org/js/telegram-web-app.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: var(--tg-theme-bg-color, #0f0f0f);
      color: var(--tg-theme-text-color, #fff);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }
    .card {
      text-align: center;
      background: var(--tg-theme-secondary-bg-color, #1a1a2e);
      padding: 48px 32px;
      border-radius: 24px;
      max-width: 340px;
      width: 90%;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    }
    .icon { font-size: 72px; margin-bottom: 20px; }
    h2 { font-size: 24px; font-weight: 700; color: #4ecca3; margin-bottom: 12px; }
    p { color: #aaa; font-size: 15px; line-height: 1.5; }
    .hint { color: #4ecca355; font-size: 13px; margin-top: 24px; }
    .btn {
      display: block; margin-top: 28px;
      background: #4ecca3; color: #000;
      padding: 14px 28px; border-radius: 12px;
      font-size: 16px; font-weight: 600;
      text-decoration: none; cursor: pointer;
      border: none; width: 100%;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h2>Device Verified!</h2>
    <p>Your device has been verified successfully.<br>Go back to Telegram and tap <b>Done</b>.</p>
    <button class="btn" onclick="Telegram.WebApp.close()">✅ Done — Close</button>
    <p class="hint">You can close this page</p>
  </div>
  <script>
    Telegram.WebApp.ready();
    Telegram.WebApp.expand();
    setTimeout(() => { try { Telegram.WebApp.close(); } catch(e){} }, 3000);
  </script>
</body>
</html>"""


def _expired_page():
    return """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Link Expired</title>
  <script src="https://telegram.org/js/telegram-web-app.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: var(--tg-theme-bg-color, #0f0f0f);
      color: var(--tg-theme-text-color, #fff);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }
    .card {
      text-align: center;
      background: var(--tg-theme-secondary-bg-color, #1a1a2e);
      padding: 48px 32px; border-radius: 24px;
      max-width: 340px; width: 90%;
    }
    .icon { font-size: 72px; margin-bottom: 20px; }
    h2 { font-size: 24px; font-weight: 700; color: #ffd93d; margin-bottom: 12px; }
    p { color: #aaa; font-size: 15px; line-height: 1.5; }
    .btn {
      display: block; margin-top: 28px;
      background: #ffd93d; color: #000;
      padding: 14px 28px; border-radius: 12px;
      font-size: 16px; font-weight: 600;
      border: none; width: 100%; cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⏰</div>
    <h2>Link Expired</h2>
    <p>This verification link has expired.<br>Go back to the bot and tap <b>Verify My Device</b> again to get a new link.</p>
    <button class="btn" onclick="Telegram.WebApp.close()">🔙 Back to Bot</button>
  </div>
  <script>
    Telegram.WebApp.ready();
    Telegram.WebApp.expand();
  </script>
</body>
</html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
