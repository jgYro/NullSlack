# Binary Analysis Slack Bot

Real-time binary file analysis with byte-pair visualization and threat detection.

## Features

- **Byte-Pair Heatmap** - Visual fingerprint of binary structure using consecutive byte frequency analysis
- **Hash Calculation** - SHA256 and MD5 for file identification
- **Entropy Analysis** - Detects packed, encrypted, or compressed files
- **VirusTotal Integration** - Cross-references file hashes against 70+ AV engines
- **Thread-Safe Processing** - Async handling prevents webhook timeouts

## Setup

### Prerequisites
- Python 3.10+
- Slack workspace with admin access
- VirusTotal API key (free tier works)

### Installation

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials
```

### Environment Variables

```
SLACK_SIGNING_SECRET    # From Slack app settings
SLACK_BOT_TOKEN         # xoxb-... token
VIRUSTOTAL_API_KEY      # From virustotal.com/gui/my-apikey
```

### Slack App Configuration

1. Create new Slack app at api.slack.com
2. Add OAuth scopes:
   - `chat:write`
   - `files:read`
   - `files:write`
   - `commands`
3. Install to workspace
4. Set Request URL: `https://your-domain.com/slack/shortcut`

## Usage

### Slash Command
```
/analyze ping              # Health check
/analyze <text>            # Process text input
```

### Message Shortcut
Right-click any message with attachments → Apps → Scan File

## Technical Details

### Entropy Ranges
- `0-3.0`: Plain text or structured data
- `3.0-6.5`: Normal executables
- `6.5-7.5`: Compressed files
- `7.5-8.0`: Encrypted/packed content

### Heatmap Interpretation
- **Dark regions**: Unused byte combinations
- **Hot spots**: Common patterns (headers, padding)
- **Diagonal lines**: Sequential data
- **Scattered points**: Random/encrypted data

### API Limits
- VirusTotal: 4 requests/minute (free tier)
- Slack file size: 1GB max
- Processing timeout: 60 seconds

## Architecture

```
Slack Event → Flask Webhook → Async Worker
                                    ↓
                            Download & Analyze
                                    ↓
                            Generate Heatmap
                                    ↓
                            Query VirusTotal
                                    ↓
                            Post Results to Thread
```

## Security Notes

- Files processed in `/tmp` and deleted after analysis
- No persistent storage of file content
- API keys stored in environment variables only
- HMAC signature verification on all Slack requests

## Deployment

### Docker
```bash
docker build -t slack-binary-analyzer .
docker run -p 3000:3000 --env-file .env slack-binary-analyzer
```

### Production
- Use reverse proxy (nginx/caddy) with HTTPS
- Set `SKIP_SLACK_SIGNATURE_VERIFY=false`
- Monitor `/healthz` endpoint
- Log rotation for Flask output

## Troubleshooting

**Bot not responding**: Check OAuth scopes and reinstall app

**Images not displaying**: Verify `files:write` scope is enabled

**VirusTotal errors**: Check API key and rate limits

**Timeout errors**: File too large or slow network, consider reducing file size limit

## License

MIT