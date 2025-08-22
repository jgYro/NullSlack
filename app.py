import os, time, hmac, hashlib, threading, json, logging, requests
from flask import Flask, request, jsonify, make_response
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv

# ---- Modular analyzers ----
from analyzers import (
    HashAnalyzer,
    VirusTotalAnalyzer,
    HeatmapAnalyzer,
    StringsAnalyzer,
    HeadersAnalyzer,
    EntropyAnalyzer,
    SummaryAnalyzer,
)

# ====== CONFIG ======
load_dotenv()  # Load .env file

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"].encode()  # from Slack
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]  # xoxb-...
SKIP_VERIFY = os.getenv("SKIP_SLACK_SIGNATURE_VERIFY", "false").lower() == "true"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")  # VT API key

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Initialize Slack WebClient
slack_client = WebClient(token=SLACK_BOT_TOKEN)


# ====== HELPERS ======
def verify_slack(req) -> bool:
    if SKIP_VERIFY:
        return True
    ts = req.headers.get("X-Slack-Request-Timestamp", "")
    sig = req.headers.get("X-Slack-Signature", "")
    if not ts or not sig:
        return False
    if abs(time.time() - int(ts)) > 60 * 5:
        return False
    body = req.get_data(as_text=True)
    base = f"v0:{ts}:{body}".encode()
    exp = "v0=" + hmac.new(SLACK_SIGNING_SECRET, base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(exp, sig)


def slack_post_json(url: str, payload: dict) -> dict:
    r = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=15,
    )
    r.raise_for_status()
    data = r.json()
    if not data.get("ok", False):
        raise RuntimeError(f"Slack API error: {data}")
    return data


def post_message(channel: str, text: str, thread_ts: str | None = None):
    payload = {"channel": channel, "text": text}
    if thread_ts:
        payload["thread_ts"] = thread_ts
    return slack_post_json("https://slack.com/api/chat.postMessage", payload)


def download_slack_file(url_private: str, dest_path: str) -> str:
    with requests.get(
        url_private,
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
        stream=True,
        timeout=60,
    ) as r:
        r.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(1 << 15):
                if chunk:
                    f.write(chunk)
    return dest_path


def try_join(channel_id: str):
    """Join public channels if allowed; ignore errors for privates/DMs."""
    try:
        requests.post(
            "https://slack.com/api/conversations.join",
            headers={
                "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
                "Content-Type": "application/json",
            },
            json={"channel": channel_id},
            timeout=10,
        ).json()
    except Exception:
        pass


# ---- File upload using Slack SDK for inline display ----
def upload_png_and_post_inline(
    channel_id: str, thread_ts: str, png_path: str, title: str
):
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

        app.logger.info(
            f"File uploaded successfully via SDK: {response.get('file', {}).get('id')}"
        )

        # The file will display inline automatically with files_upload_v2
        return {
            "file_id": response.get("file", {}).get("id"),
            "file": response.get("file", {}),
        }

    except SlackApiError as e:
        app.logger.error(f"Slack API error: {e.response['error']}")
        raise RuntimeError(f"Failed to upload file: {e.response['error']}")
    except Exception as e:
        app.logger.error(f"Unexpected error uploading file: {e}")
        raise


# ---- Helper functions ----


def post_analyzer_results(channel: str, thread_ts: str, results: list):
    """Post analyzer results to Slack thread"""
    for result in results:
        if result.success and result.slack_blocks:
            try:
                # Check if this is the strings analyzer with a JSON file
                if result.analyzer_name == "Strings Extractor" and "json_output_path" in result.data:
                    # First upload the JSON file
                    json_path = result.data["json_output_path"]
                    file_upload_success = False
                    try:
                        upload_response = slack_client.files_upload_v2(
                            channel=channel,
                            file=json_path,
                            title="Extracted Strings Data (JSON)",
                            thread_ts=thread_ts,
                        )
                        file_id = upload_response.get('file', {}).get('id')
                        file_upload_success = True
                        app.logger.info(f"Strings JSON uploaded: {file_id}")
                        
                        # Add a note about the uploaded file to the blocks
                        result.slack_blocks.append({
                            "type": "divider"
                        })
                        result.slack_blocks.append({
                            "type": "section",
                            "text": {
                                "type": "mrkdwn", 
                                "text": "*Data Export*\nComplete strings extraction data has been uploaded as JSON. File contains all extracted ASCII/UTF-16 strings and categorized findings."
                            }
                        })
                    except Exception as e:
                        app.logger.error(f"Failed to upload strings JSON: {e}")
                        result.slack_blocks.append({
                            "type": "context",
                            "elements": [{
                                "type": "mrkdwn",
                                "text": "Note: Failed to upload JSON file with full strings data"
                            }]
                        })
                
                # Post the message with results
                slack_post_json(
                    "https://slack.com/api/chat.postMessage",
                    {
                        "channel": channel,
                        "thread_ts": thread_ts,
                        "text": f"{result.analyzer_name} results",
                        "blocks": result.slack_blocks,
                    },
                )
                time.sleep(0.3)  # Small delay between messages
            except Exception as e:
                app.logger.error(f"Failed to post {result.analyzer_name} results: {e}")


# ====== WORKERS ======
def do_long_task_and_reply(response_url: str, text: str):
    try:
        time.sleep(2)
        requests.post(
            response_url,
            json={"response_type": "in_channel", "text": f"✅ Done: `{text}`"},
            timeout=10,
        )
    except Exception as e:
        requests.post(
            response_url,
            json={"response_type": "ephemeral", "text": f"⚠️ {e}"},
            timeout=10,
        )


def process_file_async(file_obj: dict, channel: str, thread_ts: str, user_id: str):
    try:
        name = file_obj.get("name", "file.bin")
        url = file_obj.get("url_private_download") or file_obj["url_private"]
        file_size = file_obj.get("size", 0)

        try_join(channel)  # make sure we can post (public channels)

        # Download to /tmp
        local = f"/tmp/{file_obj['id']}-{name}"
        png_out = f"/tmp/{file_obj['id']}-heatmap.png"
        download_slack_file(url, local)

        # Initial status message
        post_message(
            channel, f"🔍 Analyzing `{name}` ({file_size:,} bytes)...", thread_ts
        )

        # Run all analyzers
        analyzers_results = []

        # 1. Hash calculation
        hash_analyzer = HashAnalyzer()
        hash_result = hash_analyzer.safe_analyze(local)
        analyzers_results.append(hash_result)

        # 2. VirusTotal check (using hash from previous result)
        vt_analyzer = VirusTotalAnalyzer()
        file_hash = hash_result.data.get("sha256") if hash_result.success else None
        vt_result = vt_analyzer.safe_analyze(local, file_hash=file_hash)
        analyzers_results.append(vt_result)

        # 3. Heatmap generation
        heatmap_analyzer = HeatmapAnalyzer()
        heatmap_result = heatmap_analyzer.safe_analyze(local, output_dir="/tmp")

        # Upload heatmap image if generated
        if heatmap_result.success and "output_path" in heatmap_result.data:
            png_out = heatmap_result.data["output_path"]
            upload_result = upload_png_and_post_inline(
                channel_id=channel,
                thread_ts=thread_ts,
                png_path=png_out,
                title=f"Byte-Pair Heatmap — {name}",
            )

        analyzers_results.append(heatmap_result)

        # 4. Entropy analysis
        entropy_analyzer = EntropyAnalyzer()
        entropy_result = entropy_analyzer.safe_analyze(local)
        analyzers_results.append(entropy_result)

        # 5. Headers analysis
        headers_analyzer = HeadersAnalyzer()
        headers_result = headers_analyzer.safe_analyze(local)
        analyzers_results.append(headers_result)

        # 6. Strings analysis
        strings_analyzer = StringsAnalyzer(min_length=5)
        strings_result = strings_analyzer.safe_analyze(local, output_dir="/tmp")
        analyzers_results.append(strings_result)

        # Generate analysis guide (post this first)
        summary_analyzer = SummaryAnalyzer()
        summary_result = summary_analyzer.safe_analyze(local, all_results=analyzers_results)
        
        # Post guide first to help users understand the results
        if summary_result.success and summary_result.slack_blocks:
            slack_post_json(
                "https://slack.com/api/chat.postMessage",
                {
                    "channel": channel,
                    "thread_ts": thread_ts,
                    "text": "Analysis Guide",
                    "blocks": summary_result.slack_blocks,
                },
            )
            time.sleep(0.5)
        
        # Post individual analyzer results
        post_analyzer_results(channel, thread_ts, analyzers_results)

        # Clean up temporary files
        try:
            os.remove(local)
            if os.path.exists(png_out):
                os.remove(png_out)
            # Clean up JSON file if it exists
            if strings_result.success and "json_output_path" in strings_result.data:
                json_path = strings_result.data["json_output_path"]
                if os.path.exists(json_path):
                    os.remove(json_path)
        except Exception as e:
            app.logger.error(f"Cleanup error: {e}")

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
    command = form.get("command")
    text = form.get("text", "").strip()
    user_id = form.get("user_id")
    response_url = form.get("response_url")

    app.logger.info(f"Slash command {command} from {user_id}: {text!r}")

    if text.lower() == "ping":
        return jsonify(
            {
                "response_type": "in_channel",
                "text": f"🏓 PONG from {command} (invoked by <@{user_id}>)",
            }
        )

    if response_url:
        threading.Thread(
            target=do_long_task_and_reply, args=(response_url, text), daemon=True
        ).start()

    return jsonify(
        {
            "response_type": "ephemeral",
            "text": f"⏳ Working on `{text}`… results will be posted here.",
        }
    )


@app.post("/slack/shortcut")
def slack_shortcut():
    if not verify_slack(request):
        return make_response("invalid signature", 401)

    payload = json.loads(request.form["payload"])  # x-www-form-urlencoded "payload"
    if (
        payload.get("type") == "message_action"
        and payload.get("callback_id") == "scan_file"
    ):
        msg = payload["message"]
        files = msg.get("files") or []
        channel = payload["channel"]["id"]
        thread_ts = msg.get("thread_ts") or msg.get("ts")
        user_id = payload["user"]["id"]

        if not files:
            return jsonify(
                {
                    "response_action": "errors",
                    "errors": {"_": "No files found on that message."},
                }
            )

        threading.Thread(
            target=process_file_async,
            args=(files[0], channel, thread_ts, user_id),
            daemon=True,
        ).start()
        return "", 200

    return "", 200


# ====== MAIN ======
if __name__ == "__main__":
    port = int(os.getenv("PORT", "3000"))
    app.run(host="0.0.0.0", port=port, debug=False)
