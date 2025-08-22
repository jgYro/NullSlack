import os, time, hmac, hashlib, threading, json, logging, requests
from flask import Flask, request, jsonify, make_response
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
import vt

# ---- Binary viz deps (headless) ----
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm

# ====== CONFIG ======
load_dotenv()  # Load .env file

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"].encode()   # from Slack
SLACK_BOT_TOKEN      = os.environ["SLACK_BOT_TOKEN"]                 # xoxb-...
SKIP_VERIFY          = os.getenv("SKIP_SLACK_SIGNATURE_VERIFY", "false").lower() == "true"
VIRUSTOTAL_API_KEY   = os.getenv("VIRUSTOTAL_API_KEY")               # VT API key

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Initialize Slack WebClient
slack_client = WebClient(token=SLACK_BOT_TOKEN)

# ====== HELPERS ======
def verify_slack(req) -> bool:
    if SKIP_VERIFY:
        return True
    ts  = req.headers.get("X-Slack-Request-Timestamp", "")
    sig = req.headers.get("X-Slack-Signature", "")
    if not ts or not sig:
        return False
    if abs(time.time() - int(ts)) > 60 * 5:
        return False
    body = req.get_data(as_text=True)
    base = f"v0:{ts}:{body}".encode()
    exp  = "v0=" + hmac.new(SLACK_SIGNING_SECRET, base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(exp, sig)

def slack_post_json(url: str, payload: dict) -> dict:
    r = requests.post(
        url,
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}",
                 "Content-Type": "application/json"},
        json=payload, timeout=15
    )
    r.raise_for_status()
    data = r.json()
    if not data.get("ok", False):
        raise RuntimeError(f"Slack API error: {data}")
    return data

def post_message(channel: str, text: str, thread_ts: str | None = None):
    payload = {"channel": channel, "text": text}
    if thread_ts: payload["thread_ts"] = thread_ts
    return slack_post_json("https://slack.com/api/chat.postMessage", payload)

def download_slack_file(url_private: str, dest_path: str) -> str:
    with requests.get(
        url_private,
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
        stream=True, timeout=60
    ) as r:
        r.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(1 << 15):
                if chunk: f.write(chunk)
    return dest_path

def try_join(channel_id: str):
    """Join public channels if allowed; ignore errors for privates/DMs."""
    try:
        requests.post(
            "https://slack.com/api/conversations.join",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}",
                     "Content-Type": "application/json"},
            json={"channel": channel_id}, timeout=10
        ).json()
    except Exception:
        pass

# ---- File upload using Slack SDK for inline display ----
def upload_png_and_post_inline(channel_id: str, thread_ts: str, png_path: str, title: str):
    """Upload image using Slack SDK files_upload_v2 for proper inline display"""
    try:
        # Use the SDK's files_upload_v2 method which handles everything
        response = slack_client.files_upload_v2(
            channel=channel_id,
            file=png_path,
            title=title,
            initial_comment=f"📊 {title}",
            thread_ts=thread_ts,
        )
        
        app.logger.info(f"File uploaded successfully via SDK: {response.get('file', {}).get('id')}")
        
        # The file will display inline automatically with files_upload_v2
        return {
            "file_id": response.get("file", {}).get("id"),
            "file": response.get("file", {})
        }
        
    except SlackApiError as e:
        app.logger.error(f"Slack API error: {e.response['error']}")
        raise RuntimeError(f"Failed to upload file: {e.response['error']}")
    except Exception as e:
        app.logger.error(f"Unexpected error uploading file: {e}")
        raise

# ---- Security Analysis helpers ----
def calculate_file_hashes(file_path: str) -> dict:
    """Calculate SHA256 and MD5 hashes for a file."""
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
            md5_hash.update(chunk)
    
    return {
        "sha256": sha256_hash.hexdigest(),
        "md5": md5_hash.hexdigest()
    }

def calculate_entropy(file_path: str) -> float:
    """Calculate Shannon entropy of a file (0-8 bits)."""
    with open(file_path, "rb") as f:
        data = f.read()
    
    if not data:
        return 0.0
    
    # Count byte frequencies
    freq = np.zeros(256)
    for byte in data:
        freq[byte] += 1
    
    # Calculate probabilities
    probs = freq[freq > 0] / len(data)
    
    # Shannon entropy: -sum(p * log2(p))
    entropy = -np.sum(probs * np.log2(probs))
    
    return round(entropy, 3)

def check_virustotal(file_hash: str) -> dict:
    """Check file hash against VirusTotal database."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    
    try:
        with vt.Client(VIRUSTOTAL_API_KEY) as client:
            try:
                file_obj = client.get_object(f"/files/{file_hash}")
                stats = file_obj.last_analysis_stats
                
                return {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "total_engines": sum(stats.values()),
                    "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                    "reputation": file_obj.reputation if hasattr(file_obj, 'reputation') else None,
                    "names": file_obj.names[:3] if hasattr(file_obj, 'names') else [],
                }
            except vt.error.APIError as e:
                if e.code == "NotFoundError":
                    return {"found": False, "message": "File not found in VirusTotal database"}
                else:
                    return {"error": f"VirusTotal API error: {str(e)}"}
    except Exception as e:
        app.logger.error(f"VirusTotal check failed: {e}")
        return {"error": f"Failed to check VirusTotal: {str(e)}"}

# ---- Viz helpers ----
def make_bytepair_heatmap(file_path: str, out_png: str, bins: int = 256) -> dict:
    """
    2D histogram of consecutive byte pairs (b[i], b[i+1]) on a bins×bins grid.
    Log-scale intensities; save to PNG. Returns lightweight dummy metrics.
    """
    data = np.fromfile(file_path, dtype=np.uint8)
    if data.size >= 2:
        pairs = np.lib.stride_tricks.sliding_window_view(data, 2)
        x = pairs[:, 0].astype(np.int32)
        y = pairs[:, 1].astype(np.int32)
        hist, _, _ = np.histogram2d(x, y, bins=bins, range=[[0, 255], [0, 255]])
    else:
        hist = np.zeros((bins, bins), dtype=np.float64)

    plt.figure(figsize=(8, 8), dpi=100)  # Adjusted for better Slack display
    plt.imshow(
        hist.T + 1.0,
        origin="lower",
        cmap="inferno",
        norm=LogNorm(),
        extent=[0, 255, 0, 255],
        interpolation="nearest",
        aspect="equal",
    )
    plt.title("Byte-Pair Heatmap (log scale)", fontsize=14)
    plt.xlabel("byte[i]", fontsize=12)
    plt.ylabel("byte[i+1]", fontsize=12)
    plt.colorbar(label="Frequency (log scale)")
    plt.tight_layout()
    plt.savefig(out_png, format="png", bbox_inches="tight", dpi=100)
    plt.close()

    return {
        "total_bytes": int(data.size),
        "unique_bytes": int(len(np.unique(data))) if data.size else 0,
        "dummy_score": 0.73,
        "dummy_label": "likely benign",
    }

def post_blocks(channel: str, thread_ts: str, header: str, fields: dict):
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": header}},
        {"type": "section",
         "fields": [{"type": "mrkdwn", "text": f"*{k}:*\n{v}"} for k, v in fields.items()]},
    ]
    slack_post_json("https://slack.com/api/chat.postMessage",
                    {"channel": channel, "thread_ts": thread_ts,
                     "text": header, "blocks": blocks})

# ====== WORKERS ======
def do_long_task_and_reply(response_url: str, text: str):
    try:
        time.sleep(2)
        requests.post(response_url,
                      json={"response_type": "in_channel",
                            "text": f"✅ Done: `{text}`"},
                      timeout=10)
    except Exception as e:
        requests.post(response_url,
                      json={"response_type": "ephemeral",
                            "text": f"⚠️ {e}"},
                      timeout=10)

def process_file_async(file_obj: dict, channel: str, thread_ts: str, user_id: str):
    try:
        name = file_obj.get("name", "file.bin")
        url  = file_obj.get("url_private_download") or file_obj["url_private"]
        file_size = file_obj.get("size", 0)

        try_join(channel)  # make sure we can post (public channels)

        # Download to /tmp
        local   = f"/tmp/{file_obj['id']}-{name}"
        png_out = f"/tmp/{file_obj['id']}-heatmap.png"
        download_slack_file(url, local)

        # Calculate file hashes
        hashes = calculate_file_hashes(local)
        
        # Calculate entropy
        entropy = calculate_entropy(local)
        
        # Check VirusTotal
        vt_result = check_virustotal(hashes["sha256"])
        
        # Build heatmap + metrics
        metrics = make_bytepair_heatmap(local, png_out, bins=256)

        # Upload PNG - it will automatically display inline with initial_comment
        result = upload_png_and_post_inline(
            channel_id=channel,
            thread_ts=thread_ts,
            png_path=png_out,
            title=f"Byte-Pair Heatmap — {name}",
        )

        # Determine threat level emoji and text
        if vt_result.get("found"):
            malicious_count = vt_result.get("malicious", 0)
            if malicious_count == 0:
                threat_emoji = "✅"
                threat_text = "Clean"
            elif malicious_count <= 3:
                threat_emoji = "⚠️"
                threat_text = "Suspicious"
            else:
                threat_emoji = "🚨"
                threat_text = "Malicious"
        else:
            threat_emoji = "❓"
            threat_text = "Unknown (not in VT database)"
        
        # Entropy analysis
        entropy_indicator = ""
        if entropy > 7.5:
            entropy_indicator = " 🔒 (encrypted/packed)"
        elif entropy > 6.5:
            entropy_indicator = " 📦 (compressed)"
        elif entropy < 3.0:
            entropy_indicator = " 📝 (text/structured)"

        # Build comprehensive security report
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"{threat_emoji} Security Analysis: {name}"}},
            {"type": "divider"},
            
            # File Info Section
            {"type": "section",
             "text": {"type": "mrkdwn", "text": "*📄 File Information*"},
             "fields": [
                {"type": "mrkdwn", "text": f"*Filename:*\n`{name}`"},
                {"type": "mrkdwn", "text": f"*Size:*\n{file_size:,} bytes"},
                {"type": "mrkdwn", "text": f"*Entropy:*\n{entropy}/8.0{entropy_indicator}"},
                {"type": "mrkdwn", "text": f"*Unique bytes:*\n{metrics['unique_bytes']}/256"},
             ]},
            
            # Hash Section
            {"type": "section",
             "text": {"type": "mrkdwn", "text": "*🔐 File Hashes*"},
             "fields": [
                {"type": "mrkdwn", "text": f"*SHA256:*\n`{hashes['sha256']}`"},
                {"type": "mrkdwn", "text": f"*MD5:*\n`{hashes['md5']}`"},
             ]},
            
            {"type": "divider"},
        ]
        
        # VirusTotal Results Section
        if vt_result.get("found"):
            vt_fields = [
                {"type": "mrkdwn", "text": f"*Status:*\n{threat_text}"},
                {"type": "mrkdwn", "text": f"*Detection Ratio:*\n{vt_result.get('detection_ratio', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Malicious:*\n{vt_result.get('malicious', 0)} engines"},
                {"type": "mrkdwn", "text": f"*Suspicious:*\n{vt_result.get('suspicious', 0)} engines"},
            ]
            
            if vt_result.get('reputation') is not None:
                vt_fields.append({"type": "mrkdwn", "text": f"*Reputation:*\n{vt_result['reputation']}"})
            
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*🛡️ VirusTotal Analysis*"},
                "fields": vt_fields
            })
            
            if vt_result.get('names'):
                blocks.append({
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"*Known as:* {', '.join(vt_result['names'][:3])}"}]
                })
        elif vt_result.get("error"):
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*🛡️ VirusTotal Analysis*\n⚠️ {vt_result['error']}"}
            })
        else:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*🛡️ VirusTotal Analysis*\n❓ File not found in VirusTotal database (first time submission)"}
            })
        
        # Summary footer
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Analyzed by <@{user_id}> • {threat_emoji} {threat_text}"}
            ]
        })
        
        slack_post_json("https://slack.com/api/chat.postMessage",
                       {"channel": channel, "thread_ts": thread_ts,
                        "text": f"Security analysis complete for {name}: {threat_emoji} {threat_text}", 
                        "blocks": blocks})
        
        # Clean up temporary files
        try:
            os.remove(local)
            os.remove(png_out)
        except:
            pass
            
    except Exception as e:
        try:
            post_message(channel, f"⚠️ Processing failed: {e}", thread_ts)
        except Exception:
            app.logger.exception("Also failed to post error")

# ====== ROUTES ======
@app.get("/healthz")
def healthz():
    return "ok\n", 200, {"Content-Type": "text/plain"}

@app.post("/slack/commands")
def slash_commands():
    if not verify_slack(request):
        return make_response("invalid signature", 401)

    form = request.form
    command      = form.get("command")
    text         = form.get("text", "").strip()
    user_id      = form.get("user_id")
    response_url = form.get("response_url")

    app.logger.info(f"Slash command {command} from {user_id}: {text!r}")

    if text.lower() == "ping":
        return jsonify({"response_type": "in_channel",
                        "text": f"🏓 PONG from {command} (invoked by <@{user_id}>)"})

    if response_url:
        threading.Thread(
            target=do_long_task_and_reply, args=(response_url, text), daemon=True
        ).start()

    return jsonify({"response_type": "ephemeral",
                    "text": f"⏳ Working on `{text}`… results will be posted here."})

@app.post("/slack/shortcut")
def slack_shortcut():
    if not verify_slack(request):
        return make_response("invalid signature", 401)

    payload = json.loads(request.form["payload"])  # x-www-form-urlencoded "payload"
    if payload.get("type") == "message_action" and payload.get("callback_id") == "scan_file":
        msg       = payload["message"]
        files     = msg.get("files") or []
        channel   = payload["channel"]["id"]
        thread_ts = msg.get("thread_ts") or msg.get("ts")
        user_id   = payload["user"]["id"]

        if not files:
            return jsonify({"response_action": "errors",
                            "errors": {"_": "No files found on that message."}})

        threading.Thread(
            target=process_file_async,
            args=(files[0], channel, thread_ts, user_id),
            daemon=True
        ).start()
        return "", 200

    return "", 200

# ====== MAIN ======
if __name__ == "__main__":
    port = int(os.getenv("PORT", "3000"))
    app.run(host="0.0.0.0", port=port, debug=False)