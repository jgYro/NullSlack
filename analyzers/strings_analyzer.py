"""
Strings extraction analyzer
Extracts ASCII and UTF-16LE strings from binary files
"""
import re
import json
import os
from typing import List, Dict, Optional
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
    
    def save_to_json(self, data: Dict, output_path: str) -> str:
        """Save strings data to JSON file"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return output_path
    
    def analyze(self, file_path: str, output_dir: Optional[str] = "/tmp", **kwargs) -> AnalysisResult:
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
        
        # Save all strings to JSON file
        json_data = {
            "file": os.path.basename(file_path),
            "statistics": {
                "total_ascii": total_ascii,
                "total_utf16": total_utf16,
                "total_strings": total_ascii + total_utf16
            },
            "extracted_strings": {
                "ascii": strings["ascii"],
                "utf16le": strings["utf16le"]
            },
            "categorized_findings": interesting
        }
        
        # Generate output filename
        import hashlib
        file_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
        json_output_path = os.path.join(output_dir, f"strings_{file_hash}.json")
        self.save_to_json(json_data, json_output_path)
        
        # Build Slack blocks with summary only
        blocks = []
        
        # Header
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Strings Analysis*"},
            "fields": [
                {"type": "mrkdwn", "text": f"*Total Extracted:*\n{total_ascii + total_utf16} strings"},
                {"type": "mrkdwn", "text": f"*ASCII:*\n{total_ascii}"},
                {"type": "mrkdwn", "text": f"*UTF-16LE:*\n{total_utf16}"},
                {"type": "mrkdwn", "text": f"*Output:*\nJSON file"}
            ]
        })
        
        # Show categorized summary if interesting findings exist
        if interesting:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Categorized Findings Summary*"}
            })
            
            category_labels = {
                "urls": "URLs",
                "paths": "File Paths", 
                "emails": "Email Addresses",
                "ips": "IP Addresses",
                "registry": "Registry Keys",
                "crypto": "Cryptographic Terms",
                "suspicious": "Suspicious Keywords"
            }
            
            summary_fields = []
            for category, items in interesting.items():
                if items:
                    label = category_labels.get(category, category.title())
                    summary_fields.append({
                        "type": "mrkdwn", 
                        "text": f"*{label}:*\n{len(items)} found"
                    })
            
            # Add fields in pairs (Slack likes 2 columns)
            while summary_fields:
                field_pair = summary_fields[:2]
                summary_fields = summary_fields[2:]
                blocks.append({
                    "type": "section",
                    "fields": field_pair
                })
        
        # Note that JSON will be included in data for app.py to handle
        return AnalysisResult(
            analyzer_name="Strings Extractor",
            success=True,
            data={
                "total_strings": total_ascii + total_utf16,
                "ascii_count": total_ascii,
                "utf16_count": total_utf16,
                "interesting": interesting,
                "json_output_path": json_output_path,
                "json_data": json_data  # Include the data for potential inline display
            },
            slack_blocks=blocks
        )