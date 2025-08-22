"""
Strings extraction analyzer
Extracts ASCII and UTF-16LE strings from binary files
"""
import re
from typing import List, Dict
from .base import BaseAnalyzer, AnalysisResult

class StringsAnalyzer(BaseAnalyzer):
    """Extract readable strings from binary files"""
    
    def __init__(self, min_length: int = 4):
        super().__init__()
        self.min_length = min_length
    
    def extract_strings(self, data: bytes) -> Dict[str, List[str]]:
        """Extract both ASCII and UTF-16LE strings"""
        strings = {
            "ascii": [],
            "utf16le": []
        }
        
        # ASCII strings
        ascii_pattern = rb"[ -~]{%d,}" % self.min_length
        for match in re.finditer(ascii_pattern, data):
            try:
                s = match.group().decode("ascii", "ignore")
                if s:
                    strings["ascii"].append(s)
            except:
                pass
        
        # UTF-16LE strings (printables + nulls)
        utf16_pattern = rb"(?:[ -~]\x00){%d,}" % self.min_length
        for match in re.finditer(utf16_pattern, data):
            try:
                s = match.group().decode("utf-16le", "ignore")
                if s:
                    strings["utf16le"].append(s)
            except:
                pass
        
        return strings
    
    def find_interesting_strings(self, strings: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Identify potentially interesting strings"""
        interesting = {
            "urls": [],
            "paths": [],
            "emails": [],
            "ips": [],
            "registry": [],
            "crypto": [],
            "suspicious": []
        }
        
        all_strings = strings["ascii"] + strings["utf16le"]
        
        for s in all_strings:
            # URLs
            if re.search(r"https?://", s, re.IGNORECASE):
                interesting["urls"].append(s)
            
            # File paths (Windows or Unix-like)
            if re.search(r"[C-Z]:\\|\/usr\/|\/opt\/|\/etc\/|\/var\/|\/home\/|\/lib\/|\/bin\/", s):
                interesting["paths"].append(s)
            elif re.search(r"\.dll$|\.exe$|\.dylib$|\.so$|\.sys$", s, re.IGNORECASE):
                interesting["paths"].append(s)
            
            # Emails
            if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", s):
                interesting["emails"].append(s)
            
            # IPs
            if re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", s):
                interesting["ips"].append(s)
            
            # Registry keys
            if re.search(r"HKEY_|SOFTWARE\\|SYSTEM\\", s):
                interesting["registry"].append(s)
            
            # Crypto indicators
            if re.search(r"RSA|AES|SHA|MD5|BASE64|ENCRYPT|DECRYPT|KEY|CIPHER", s, re.IGNORECASE):
                interesting["crypto"].append(s)
            
            # Suspicious keywords
            if re.search(r"password|admin|root|cmd\.exe|powershell|download|upload|inject|hook|patch|askpassword|ftppassword|authentication", s, re.IGNORECASE):
                interesting["suspicious"].append(s)
        
        # Remove empty categories (but don't limit results yet)
        return {k: v for k, v in interesting.items() if v}
    
    def analyze(self, file_path: str, **kwargs) -> AnalysisResult:
        """Analyze strings in the file"""
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Extract strings
        strings = self.extract_strings(data)
        
        # Find interesting patterns
        interesting = self.find_interesting_strings(strings)
        
        # Count statistics
        total_ascii = len(strings["ascii"])
        total_utf16 = len(strings["utf16le"])
        
        # Build Slack blocks
        blocks = []
        
        # Header
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "🔤 *Strings Analysis*"},
            "fields": [
                {"type": "mrkdwn", "text": f"*ASCII strings:*\n{total_ascii}"},
                {"type": "mrkdwn", "text": f"*UTF-16 strings:*\n{total_utf16}"}
            ]
        })
        
        # Interesting findings
        if interesting:
            blocks.append({"type": "divider"})
            
            for category, items in interesting.items():
                if items:
                    emoji_map = {
                        "urls": "🌐",
                        "paths": "📁", 
                        "emails": "📧",
                        "ips": "🔢",
                        "registry": "🔧",
                        "crypto": "🔐",
                        "suspicious": "⚠️"
                    }
                    emoji = emoji_map.get(category, "•")
                    
                    # Show ALL items without truncation
                    items_text = "\n".join([
                        f"• `{item}`" 
                        for item in items
                    ])
                    
                    blocks.append({
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"{emoji} *{category.title()}* ({len(items)} found)\n{items_text}"}
                    })
        
        # Show total counts as context
        if strings["ascii"] or strings["utf16le"]:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"📊 *Total extracted:* {total_ascii} ASCII strings, {total_utf16} UTF-16LE strings"}]
            })
        
        return AnalysisResult(
            analyzer_name="Strings Extractor",
            success=True,
            data={
                "total_strings": total_ascii + total_utf16,
                "ascii_count": total_ascii,
                "utf16_count": total_utf16,
                "interesting": interesting
            },
            slack_blocks=blocks
        )