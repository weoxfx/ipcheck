"""
Xeo IP Verification Server
Deploy this on Render/Railway (free tier).

Environment variables to set on Render/Railway:
  SECRET  — same random string as in your main bot
  PORT    — set automatically (don't touch)

No BOT_TOKEN needed here at all!

Flow:
  1. Bot sends user a link: https://your-app.onrender.com/verify?token=XXXX
  2. User opens it — server reads real IP, stores result
  3. Bot polls /result?token=XXXX to get the IP hash
  4. Bot records it and grants/blocks access
"""

import os
import hashlib
import hmac
import time
from flask import Flask, request, jsonify

app    = Flask(__name__)
SECRET = os.environ.get("SECRET", "xeo_fp_secret_change_me")

# In-memory store: token -> {"ip_hash": ..., "ts": ...}
# Results expire after 10 minutes
results = {}

# ── Helpers ───────────────────────────────────────────────────────────────────

def verify_token(token: str, max_age: int = 300):
    """Returns user_id if token is valid and not expired, else None."""
    try:
        uid, ts, sig = token.split("_")
        uid, ts      = int(uid), int(ts)
        if time.time() - ts > max_age:
            return None
        raw      = f"{uid}:{ts}"
        expected = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(expected, sig):
            return None
        return uid
    except Exception:
        return None

def hash_ip(ip: str) -> str:
    return hashlib.sha256((SECRET + ip).encode()).hexdigest()

def get_real_ip() -> str:
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP", "")
        or request.remote_addr
        or "unknown"
    )

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/verify")
def verify():
    """User opens this link. We read their IP and store the result."""
    token   = request.args.get("token", "")
    user_id = verify_token(token)

    if not user_id:
        return """
        <html><body style="background:#0f0f0f;color:#fff;font-family:sans-serif;
        display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
        <div style="text-align:center">
          <div style="font-size:64px">⏰</div>
          <h2 style="color:#ffd93d">Link Expired</h2>
          <p style="color:#aaa">Go back to the bot and tap Verify again.</p>
        </div></body></html>
        """, 400

    ip      = get_real_ip()
    ip_hash = hash_ip(ip)

    # Store result for the bot to pick up
    results[token] = {"ip_hash": ip_hash, "user_id": user_id, "ts": time.time()}

    return """
    <html><body style="background:#0f0f0f;color:#fff;font-family:sans-serif;
    display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
    <div style="text-align:center;background:#1a1a2e;padding:40px 30px;border-radius:20px;max-width:340px">
      <div style="font-size:64px">✅</div>
      <h2 style="color:#4ecca3;margin:16px 0 8px">Device Verified!</h2>
      <p style="color:#aaa">Go back to Telegram — your account will unlock automatically.</p>
      <p style="color:#4ecca366;font-size:13px;margin-top:20px">You can close this page</p>
    </div></body></html>
    """

@app.route("/result")
def result():
    """Bot polls this to get the IP hash after user verifies."""
    token = request.args.get("token", "")

    # Clean up expired results (older than 10 min)
    now = time.time()
    expired = [k for k, v in results.items() if now - v["ts"] > 600]
    for k in expired:
        results.pop(k, None)

    if token not in results:
        return jsonify({"ready": False})

    data = results.pop(token)  # consume it — one use only
    return jsonify({"ready": True, "ip_hash": data["ip_hash"], "user_id": data["user_id"]})

@app.route("/ping")
def ping():
    return jsonify({"status": "ok"})

# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
