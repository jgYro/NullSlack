"""
VirusTotal integration analyzer
Checks file hashes against VirusTotal database
"""
import os
import vt
from typing import Dict, Optional
from .base import BaseAnalyzer, AnalysisResult

class VirusTotalAnalyzer(BaseAnalyzer):
    """Check files against VirusTotal database"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__()
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
    
    def check_hash(self, file_hash: str) -> Dict:
        """Check a file hash against VirusTotal"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            with vt.Client(self.api_key) as client:
                try:
                    file_obj = client.get_object(f"/files/{file_hash}")
                    stats = file_obj.last_analysis_stats
                    
                    result = {
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
                    
                    # Get additional metadata if available
                    if hasattr(file_obj, 'type_description'):
                        result["type"] = file_obj.type_description
                    if hasattr(file_obj, 'size'):
                        result["size"] = file_obj.size
                    if hasattr(file_obj, 'first_submission_date'):
                        result["first_seen"] = str(file_obj.first_submission_date)
                    
                    return result
                    
                except vt.error.APIError as e:
                    if e.code == "NotFoundError":
                        return {"found": False, "message": "File not found in VirusTotal database"}
                    else:
                        return {"error": f"VirusTotal API error: {str(e)}"}
        except Exception as e:
            return {"error": f"Failed to check VirusTotal: {str(e)}"}
    
    def analyze(self, file_path: str, file_hash: Optional[str] = None, **kwargs) -> AnalysisResult:
        """Analyze file against VirusTotal"""
        # If no hash provided, calculate SHA256
        if not file_hash:
            import hashlib
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
            file_hash = sha256_hash.hexdigest()
        
        # Check VirusTotal
        vt_result = self.check_hash(file_hash)
        
        # Build Slack blocks
        blocks = []
        
        if vt_result.get("error"):
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"🛡️ *VirusTotal Analysis*\n⚠️ {vt_result['error']}"}
            })
        elif not vt_result.get("found"):
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "🛡️ *VirusTotal Analysis*\n❓ File not found in database (first time submission)"}
            })
        else:
            # Determine threat level
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
            
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"🛡️ *VirusTotal Analysis* {threat_emoji}"},
                "fields": [
                    {"type": "mrkdwn", "text": f"*Status:*\n{threat_text}"},
                    {"type": "mrkdwn", "text": f"*Detection:*\n{vt_result['detection_ratio']}"},
                    {"type": "mrkdwn", "text": f"*Malicious:*\n{vt_result['malicious']} engines"},
                    {"type": "mrkdwn", "text": f"*Suspicious:*\n{vt_result['suspicious']} engines"}
                ]
            })
            
            # Additional metadata
            if vt_result.get("type"):
                blocks.append({
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"*File Type:* {vt_result['type']}"}]
                })
            
            if vt_result.get("names"):
                names_text = ", ".join(vt_result["names"][:3])
                blocks.append({
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"*Known as:* {names_text}"}]
                })
            
            if vt_result.get("reputation") is not None:
                blocks.append({
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"*Reputation Score:* {vt_result['reputation']}"}]
                })
        
        return AnalysisResult(
            analyzer_name="VirusTotal Scanner",
            success=True,
            data=vt_result,
            slack_blocks=blocks
        )