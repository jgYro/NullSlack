"""
File hash calculator analyzer
Calculates cryptographic hashes for file identification
"""
import hashlib
from typing import Dict
from .base import BaseAnalyzer, AnalysisResult

class HashAnalyzer(BaseAnalyzer):
    """Calculate cryptographic hashes for files"""
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple hash types for a file"""
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
        
        return {
            "sha256": sha256_hash.hexdigest(),
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest()
        }
    
    def analyze(self, file_path: str, **kwargs) -> AnalysisResult:
        """Calculate file hashes"""
        hashes = self.calculate_hashes(file_path)
        
        # Build Slack blocks
        blocks = [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": "🔐 *File Hashes*"},
            "fields": [
                {"type": "mrkdwn", "text": f"*SHA256:*\n`{hashes['sha256']}`"},
                {"type": "mrkdwn", "text": f"*MD5:*\n`{hashes['md5']}`"}
            ]
        }]
        
        # Add SHA1 in context
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"*SHA1:* `{hashes['sha1']}`"}]
        })
        
        return AnalysisResult(
            analyzer_name="Hash Calculator",
            success=True,
            data=hashes,
            slack_blocks=blocks
        )