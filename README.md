# Binary Analysis Slack Bot

Comprehensive binary file analysis with multi-layered security inspection and threat detection.

## Features

### Core Analysis
- **Byte-Pair Heatmap** - Visual fingerprint of binary structure using consecutive byte frequency analysis
- **Hash Calculation** - SHA256 and MD5 for file identification
- **Entropy Analysis** - Detects packed, encrypted, or compressed files with section-level analysis
- **VirusTotal Integration** - Cross-references file hashes against 70+ AV engines

### Advanced Modules
- **Strings Extraction** - ASCII and UTF-16LE string extraction with pattern detection
  - URL, IP, email detection
  - Registry key identification
  - Crypto/encryption indicators
  - Suspicious keyword flagging
  
- **Binary Headers Inspector** - Deep analysis using LIEF
  - PE: Imports, exports, sections, DLL characteristics, security features
  - ELF: Libraries, symbols, security (NX, PIE, RELRO)
  - Mach-O: Architectures, code signing, load commands
  
- **Entropy Scanner** - Advanced entropy analysis
  - Sliding window detection for packed regions
  - Per-section entropy calculation
  - Variance analysis for encryption detection
  - Classification (text, code, compressed, encrypted)

### Infrastructure
- **Thread-Safe Processing** - Async handling prevents webhook timeouts
- **Modular Architecture** - Extensible analyzer framework

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

### Analysis Pipeline
Each uploaded file goes through multiple analysis stages:
1. **Hash calculation** (SHA256, MD5)
2. **VirusTotal lookup** 
3. **Byte-pair heatmap generation**
4. **Strings extraction** (ASCII, UTF-16LE)
5. **Binary headers parsing** (PE/ELF/Mach-O)
6. **Entropy analysis** (file and section level)

Results are posted as separate messages in the thread for clarity.

### Entropy Ranges
- `0-3.0`: Plain text or structured data
- `3.0-6.5`: Normal executables
- `6.5-7.2`: Compressed files
- `7.2-7.8`: Heavily compressed
- `7.8-8.0`: Encrypted/packed content

### Heatmap Interpretation
- **Dark regions**: Unused byte combinations
- **Hot spots**: Common patterns (headers, padding)
- **Diagonal lines**: Sequential data
- **Scattered points**: Random/encrypted data

### Binary Format Support
- **PE** (Windows): Full import/export analysis, security features detection
- **ELF** (Linux): Symbol analysis, security mitigations check
- **Mach-O** (macOS): Multi-architecture support, code signing verification

### API Limits
- VirusTotal: 4 requests/minute (free tier)
- Slack file size: 1GB max
- Processing timeout: 60 seconds
- LIEF parsing: Most common binary formats

## Architecture

### Processing Flow
```
Slack Event → Flask Webhook → Async Worker Thread
                                    ↓
                            Download File to /tmp
                                    ↓
                    ┌───────────────┴───────────────┐
                    │     Parallel Analysis Phase    │
                    ├────────────────────────────────┤
                    │ • Hash Calculation (SHA256/MD5)│
                    │ • VirusTotal API Check        │
                    │ • Byte-Pair Heatmap Generation│
                    │ • Modular Analyzers:          │
                    │   - Strings Extraction        │
                    │   - Headers Inspection (LIEF) │
                    │   - Entropy Scanning          │
                    └────────────────────────────────┘
                                    ↓
                        Post Results to Slack Thread
                        (Multiple formatted messages)
```

### Module Structure
```
slack/
├── app.py                 # Main Flask application
├── analyzers/            # Modular analysis components
│   ├── __init__.py
│   ├── base.py           # Base classes and interfaces
│   ├── strings_analyzer.py
│   ├── headers_analyzer.py
│   └── entropy_analyzer.py
├── requirements.txt
└── .env                  # API keys and secrets
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

## Extending the Framework

### Adding New Analyzers
Create a new analyzer in `analyzers/` directory:

```python
from analyzers.base import BaseAnalyzer, AnalysisResult

class CustomAnalyzer(BaseAnalyzer):
    def analyze(self, file_path: str, **kwargs) -> AnalysisResult:
        # Your analysis logic
        data = {"key": "value"}
        
        # Build Slack blocks
        blocks = [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Custom Analysis*"},
            "fields": [...]
        }]
        
        return AnalysisResult(
            analyzer_name="Custom Analyzer",
            success=True,
            data=data,
            slack_blocks=blocks
        )
```

Then import and use in `app.py`:
```python
from analyzers import CustomAnalyzer
custom = CustomAnalyzer()
result = custom.safe_analyze(file_path)
```

## Troubleshooting

**Bot not responding**: Check OAuth scopes and reinstall app

**Images not displaying**: Verify `files:write` scope is enabled

**VirusTotal errors**: Check API key and rate limits

**LIEF parsing errors**: File may be corrupted or unsupported format

**Timeout errors**: File too large or slow network, consider reducing file size limit

## Dependencies

- **Flask**: Web framework for webhook handling
- **slack-sdk**: Official Slack Python SDK
- **python-dotenv**: Environment variable management
- **vt-py**: VirusTotal API client
- **numpy**: Numerical operations for entropy
- **matplotlib**: Heatmap visualization
- **lief**: Binary format parsing (PE/ELF/Mach-O)
- **requests**: HTTP client

## License

MIT