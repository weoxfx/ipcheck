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

# ── HTML Templates ────────────────────────────────────────────────────────────

EXPIRED_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Link Expired — Xeo</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #080810;
    --surface: #0e0e1a;
    --border: rgba(255,200,60,0.15);
    --gold: #ffc83c;
    --gold-dim: rgba(255,200,60,0.4);
    --text: #e8e8f0;
    --muted: #6b6b88;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'DM Sans', sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }

  /* Ambient background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background:
      radial-gradient(ellipse 60% 40% at 50% 0%, rgba(255,200,60,0.06) 0%, transparent 70%),
      radial-gradient(ellipse 40% 60% at 80% 80%, rgba(255,160,20,0.04) 0%, transparent 60%);
    pointer-events: none;
  }

  /* Animated grid */
  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(255,200,60,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,200,60,0.03) 1px, transparent 1px);
    background-size: 48px 48px;
    animation: gridScroll 20s linear infinite;
    pointer-events: none;
  }

  @keyframes gridScroll {
    0% { transform: translateY(0); }
    100% { transform: translateY(48px); }
  }

  .card {
    position: relative;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 24px;
    padding: 56px 48px;
    max-width: 400px;
    width: calc(100% - 48px);
    text-align: center;
    animation: cardIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) both;
    box-shadow:
      0 0 0 1px rgba(255,200,60,0.05),
      0 32px 64px rgba(0,0,0,0.6),
      inset 0 1px 0 rgba(255,255,255,0.04);
  }

  @keyframes cardIn {
    from { opacity: 0; transform: translateY(24px) scale(0.96); }
    to   { opacity: 1; transform: translateY(0) scale(1); }
  }

  /* Corner accents */
  .card::before, .card::after {
    content: '';
    position: absolute;
    width: 20px;
    height: 20px;
    border-color: var(--gold-dim);
    border-style: solid;
  }
  .card::before { top: -1px; left: -1px; border-width: 2px 0 0 2px; border-radius: 24px 0 0 0; }
  .card::after  { bottom: -1px; right: -1px; border-width: 0 2px 2px 0; border-radius: 0 0 24px 0; }

  .icon-wrap {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 88px;
    height: 88px;
    margin-bottom: 28px;
    animation: iconIn 0.7s cubic-bezier(0.16, 1, 0.3, 1) 0.15s both;
  }

  @keyframes iconIn {
    from { opacity: 0; transform: scale(0.5) rotate(-20deg); }
    to   { opacity: 1; transform: scale(1) rotate(0deg); }
  }

  .icon-wrap::before {
    content: '';
    position: absolute;
    inset: 0;
    border-radius: 50%;
    background: rgba(255,200,60,0.08);
    border: 1px solid rgba(255,200,60,0.2);
    animation: iconPulse 2.5s ease-in-out infinite;
  }

  @keyframes iconPulse {
    0%, 100% { transform: scale(1); opacity: 1; }
    50% { transform: scale(1.12); opacity: 0.6; }
  }

  .icon-wrap svg {
    width: 44px;
    height: 44px;
    position: relative;
    z-index: 1;
  }

  h1 {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 26px;
    color: var(--gold);
    letter-spacing: -0.5px;
    margin-bottom: 12px;
    animation: textIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.25s both;
  }

  p {
    font-size: 15px;
    line-height: 1.6;
    color: var(--muted);
    animation: textIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.35s both;
  }

  .hint {
    margin-top: 28px;
    padding: 14px 20px;
    background: rgba(255,200,60,0.05);
    border: 1px solid rgba(255,200,60,0.12);
    border-radius: 12px;
    font-size: 13px;
    color: rgba(255,200,60,0.7);
    animation: textIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.45s both;
  }

  @keyframes textIn {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .brand {
    position: fixed;
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%);
    font-family: 'Syne', sans-serif;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 2px;
    color: rgba(255,255,255,0.12);
    text-transform: uppercase;
  }
</style>
</head>
<body>
<div class="card">
  <div class="icon-wrap">
    <svg viewBox="0 0 24 24" fill="none" stroke="#ffc83c" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <polyline points="12 6 12 12 16 14"/>
    </svg>
  </div>
  <h1>Link Expired</h1>
  <p>This verification link is no longer valid.<br>Verification links expire after 5 minutes.</p>
  <div class="hint">↩ Go back to the bot and tap <strong>Verify</strong> to get a new link.</div>
</div>
<div class="brand">Xeo Wallet</div>
</body>
</html>"""

SUCCESS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verified — Xeo</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #050d0a;
    --surface: #080f0c;
    --border: rgba(60,240,150,0.12);
    --green: #3cf096;
    --green-dim: rgba(60,240,150,0.3);
    --text: #e0f0e8;
    --muted: #4a7060;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'DM Sans', sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }

  /* Ambient glow */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background:
      radial-gradient(ellipse 70% 50% at 50% 30%, rgba(60,240,150,0.05) 0%, transparent 65%),
      radial-gradient(ellipse 40% 40% at 20% 70%, rgba(20,200,100,0.03) 0%, transparent 60%);
    pointer-events: none;
  }

  /* Particle canvas */
  #particles {
    position: fixed;
    inset: 0;
    pointer-events: none;
  }

  .card {
    position: relative;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 28px;
    padding: 56px 48px 48px;
    max-width: 400px;
    width: calc(100% - 48px);
    text-align: center;
    animation: cardIn 0.7s cubic-bezier(0.16, 1, 0.3, 1) both;
    box-shadow:
      0 0 0 1px rgba(60,240,150,0.04),
      0 40px 80px rgba(0,0,0,0.7),
      0 0 120px rgba(60,240,150,0.04),
      inset 0 1px 0 rgba(60,240,150,0.06);
  }

  @keyframes cardIn {
    from { opacity: 0; transform: translateY(32px) scale(0.94); }
    to   { opacity: 1; transform: translateY(0) scale(1); }
  }

  /* Corner accents */
  .card::before, .card::after {
    content: '';
    position: absolute;
    width: 24px;
    height: 24px;
    border-color: var(--green-dim);
    border-style: solid;
  }
  .card::before { top: -1px; left: -1px; border-width: 2px 0 0 2px; border-radius: 28px 0 0 0; }
  .card::after  { bottom: -1px; right: -1px; border-width: 0 2px 2px 0; border-radius: 0 0 28px 0; }

  /* Checkmark animation */
  .check-wrap {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 96px;
    height: 96px;
    margin-bottom: 32px;
  }

  .check-ring {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    border: 2px solid var(--green-dim);
    animation: ringPulse 2s ease-out 0.4s both;
  }

  .check-ring-2 {
    position: absolute;
    inset: -12px;
    border-radius: 50%;
    border: 1px solid rgba(60,240,150,0.1);
    animation: ringPulse 2s ease-out 0.6s both;
  }

  @keyframes ringPulse {
    0% { transform: scale(0.6); opacity: 0; }
    50% { opacity: 1; }
    100% { transform: scale(1); opacity: 0.6; }
  }

  .check-bg {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(60,240,150,0.12) 0%, transparent 70%);
    animation: bgGlow 1s ease-out 0.3s both;
  }

  @keyframes bgGlow {
    from { opacity: 0; transform: scale(0.5); }
    to   { opacity: 1; transform: scale(1); }
  }

  .check-svg {
    position: relative;
    z-index: 1;
    width: 48px;
    height: 48px;
  }

  .check-path {
    stroke-dasharray: 60;
    stroke-dashoffset: 60;
    animation: drawCheck 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.4s forwards;
  }

  @keyframes drawCheck {
    to { stroke-dashoffset: 0; }
  }

  /* Ripple effect */
  .ripple {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    border: 1px solid var(--green);
    animation: rippleOut 1.5s ease-out 0.5s both;
  }
  .ripple:nth-child(2) { animation-delay: 0.8s; }
  .ripple:nth-child(3) { animation-delay: 1.1s; }

  @keyframes rippleOut {
    from { transform: scale(1); opacity: 0.6; }
    to   { transform: scale(2.2); opacity: 0; }
  }

  h1 {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 28px;
    color: var(--green);
    letter-spacing: -0.5px;
    margin-bottom: 10px;
    animation: textIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.55s both;
  }

  .subtitle {
    font-size: 15px;
    line-height: 1.65;
    color: rgba(224,240,232,0.6);
    margin-bottom: 32px;
    animation: textIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.65s both;
  }

  .steps {
    display: flex;
    flex-direction: column;
    gap: 10px;
    animation: textIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.75s both;
  }

  .step {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 14px 18px;
    background: rgba(60,240,150,0.04);
    border: 1px solid rgba(60,240,150,0.08);
    border-radius: 12px;
    text-align: left;
    font-size: 14px;
    color: rgba(224,240,232,0.7);
    transition: border-color 0.3s;
  }

  .step.done {
    border-color: rgba(60,240,150,0.2);
    color: var(--text);
  }

  .step-dot {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    border: 1px solid rgba(60,240,150,0.3);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    font-size: 13px;
    color: var(--green);
    font-weight: 600;
  }

  .step.done .step-dot {
    background: rgba(60,240,150,0.12);
    border-color: var(--green-dim);
  }

  .notice {
    margin-top: 24px;
    font-size: 12px;
    color: rgba(60,240,150,0.35);
    animation: textIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.85s both;
    letter-spacing: 0.3px;
  }

  @keyframes textIn {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .brand {
    position: fixed;
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%);
    font-family: 'Syne', sans-serif;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 2px;
    color: rgba(255,255,255,0.1);
    text-transform: uppercase;
    white-space: nowrap;
  }
</style>
</head>
<body>
<canvas id="particles"></canvas>

<div class="card">
  <div class="check-wrap">
    <div class="check-bg"></div>
    <div class="check-ring"></div>
    <div class="check-ring-2"></div>
    <div class="ripple"></div>
    <div class="ripple"></div>
    <div class="ripple"></div>
    <svg class="check-svg" viewBox="0 0 48 48" fill="none">
      <path class="check-path" d="M12 25l9 9 15-18"
        stroke="#3cf096" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  </div>

  <h1>Device Verified!</h1>
  <p class="subtitle">Your IP address has been securely recorded<br>to prevent duplicate accounts.</p>

  <div class="steps">
    <div class="step done">
      <div class="step-dot">✓</div>
      <span>Device fingerprint recorded</span>
    </div>
    <div class="step done">
      <div class="step-dot">✓</div>
      <span>Identity confirmed</span>
    </div>
    <div class="step">
      <div class="step-dot">3</div>
      <span>Tap <strong>✅ Done</strong> in Telegram to unlock</span>
    </div>
  </div>

  <p class="notice">🔒 Your data is hashed and never stored in plain text</p>
</div>

<div class="brand">Xeo Wallet</div>

<script>
// Floating particles
const canvas = document.getElementById('particles');
const ctx = canvas.getContext('2d');
let W, H, particles = [];

function resize() {
  W = canvas.width  = window.innerWidth;
  H = canvas.height = window.innerHeight;
}
resize();
window.addEventListener('resize', resize);

function mkParticle() {
  return {
    x: Math.random() * W,
    y: Math.random() * H,
    r: Math.random() * 1.5 + 0.3,
    vx: (Math.random() - 0.5) * 0.3,
    vy: -Math.random() * 0.5 - 0.2,
    alpha: Math.random() * 0.5 + 0.1,
    life: 0,
    maxLife: Math.random() * 200 + 100
  };
}

for (let i = 0; i < 60; i++) particles.push(mkParticle());

function draw() {
  ctx.clearRect(0, 0, W, H);
  particles.forEach((p, i) => {
    p.life++;
    p.x += p.vx;
    p.y += p.vy;
    const fade = Math.min(p.life / 30, 1) * Math.max(1 - p.life / p.maxLife, 0);
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(60,240,150,${p.alpha * fade})`;
    ctx.fill();
    if (p.life >= p.maxLife || p.y < 0) particles[i] = mkParticle();
  });
  requestAnimationFrame(draw);
}
draw();

// Animate step 3 highlight after delay
setTimeout(() => {
  document.querySelectorAll('.step')[2].style.borderColor = 'rgba(60,240,150,0.25)';
  document.querySelectorAll('.step')[2].style.color = 'rgba(224,240,232,0.9)';
}, 1200);
</script>
</body>
</html>"""

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/verify")
def verify():
    """User opens this link. We read their IP and store the result."""
    token   = request.args.get("token", "")
    user_id = verify_token(token)

    if not user_id:
        return EXPIRED_HTML, 400

    ip      = get_real_ip()
    ip_hash = hash_ip(ip)

    # Store result for the bot to pick up
    results[token] = {"ip_hash": ip_hash, "user_id": user_id, "ts": time.time()}

    return SUCCESS_HTML

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
