import os, time, hmac, hashlib, threading, json, logging, requests
from flask import Flask, request, jsonify, make_response
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# ---- Binary viz deps (headless) ----
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm

# ====== CONFIG ======
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"].encode()   # from Slack
SLACK_BOT_TOKEN      = os.environ["SLACK_BOT_TOKEN"]                 # xoxb-...
SKIP_VERIFY          = os.getenv("SKIP_SLACK_SIGNATURE_VERIFY", "false").lower() == "true"

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

        try_join(channel)  # make sure we can post (public channels)

        # Download to /tmp
        local   = f"/tmp/{file_obj['id']}-{name}"
        png_out = f"/tmp/{file_obj['id']}-heatmap.png"
        download_slack_file(url, local)

        # Build heatmap + dummy metrics
        metrics = make_bytepair_heatmap(local, png_out, bins=256)

        # Upload PNG - it will automatically display inline with initial_comment
        result = upload_png_and_post_inline(
            channel_id=channel,
            thread_ts=thread_ts,
            png_path=png_out,
            title=f"Byte-Pair Heatmap — {name}",
        )

        # Post summary with the heatmap as an attachment block
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"Analysis summary for `{name}`"}},
            {"type": "section",
             "fields": [
                {"type": "mrkdwn", "text": f"*Bytes:*\n{metrics['total_bytes']}"},
                {"type": "mrkdwn", "text": f"*Unique bytes:*\n{metrics['unique_bytes']}"},
                {"type": "mrkdwn", "text": f"*Dummy score:*\n{metrics['dummy_score']}"},
                {"type": "mrkdwn", "text": f"*Dummy label:*\n{metrics['dummy_label']}"},
             ]},
        ]
        
        slack_post_json("https://slack.com/api/chat.postMessage",
                       {"channel": channel, "thread_ts": thread_ts,
                        "text": f"Analysis complete for {name}", "blocks": blocks})
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