"""
Entropy scanning analyzer
Analyzes file and section entropy for detecting packed/encrypted content
"""
import math
import numpy as np
from collections import Counter
from typing import Dict, List, Tuple, Optional
try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

from .base import BaseAnalyzer, AnalysisResult

class EntropyAnalyzer(BaseAnalyzer):
    """Analyze entropy of files and sections"""
    
    def __init__(self, window_size: int = 4096, high_entropy_threshold: float = 7.2):
        super().__init__()
        self.window_size = window_size
        self.high_entropy_threshold = high_entropy_threshold
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data (0-8 bits)"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        freq = Counter(data)
        length = len(data)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return round(entropy, 4)
    
    def scan_entropy_windows(self, data: bytes) -> List[Tuple[int, float]]:
        """Scan for high-entropy regions using sliding window"""
        high_entropy_regions = []
        
        for i in range(0, len(data), self.window_size):
            window = data[i:i + self.window_size]
            if len(window) < self.window_size // 2:  # Skip small final window
                break
            
            entropy = self.calculate_entropy(window)
            if entropy >= self.high_entropy_threshold:
                high_entropy_regions.append((i, entropy))
        
        return high_entropy_regions
    
    def analyze_sections(self, file_path: str) -> Optional[List[Dict]]:
        """Analyze entropy per section if binary format"""
        if not HAS_LIEF:
            return None
        
        try:
            binary = lief.parse(file_path)
            if not binary or not hasattr(binary, 'sections'):
                return None
            
            sections_entropy = []
            for section in binary.sections:
                if hasattr(section, 'content'):
                    content = bytes(section.content)
                    if content:
                        entropy = self.calculate_entropy(content)
                        sections_entropy.append({
                            "name": section.name if section.name else f"section_{len(sections_entropy)}",
                            "size": len(content),
                            "entropy": entropy,
                            "suspicious": entropy >= self.high_entropy_threshold
                        })
            
            # Sort by entropy (highest first)
            sections_entropy.sort(key=lambda x: x["entropy"], reverse=True)
            return sections_entropy
            
        except Exception:
            return None
    
    def classify_entropy(self, entropy: float) -> Tuple[str, str]:
        """Classify entropy level and return label with emoji"""
        if entropy < 1.0:
            return "Empty/Zeros", "⬜"
        elif entropy < 3.0:
            return "Text/Structured", "📝"
        elif entropy < 5.0:
            return "Code/Binary", "⚙️"
        elif entropy < 6.5:
            return "Normal Binary", "📊"
        elif entropy < 7.2:
            return "Compressed", "📦"
        elif entropy < 7.8:
            return "Heavily Compressed", "🗜️"
        else:
            return "Encrypted/Packed", "🔒"
    
    def analyze(self, file_path: str, **kwargs) -> AnalysisResult:
        """Perform entropy analysis on the file"""
        # Read file
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Calculate overall entropy
        overall_entropy = self.calculate_entropy(data)
        classification, emoji = self.classify_entropy(overall_entropy)
        
        # Find high-entropy windows
        high_entropy_regions = self.scan_entropy_windows(data)
        
        # Analyze sections if possible
        sections_entropy = self.analyze_sections(file_path)
        
        # Calculate entropy distribution
        chunk_size = max(1, len(data) // 100)  # 100 samples
        distribution = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            if chunk:
                distribution.append(self.calculate_entropy(chunk))
        
        if distribution:
            entropy_variance = np.var(distribution)
            entropy_std = np.std(distribution)
        else:
            entropy_variance = 0
            entropy_std = 0
        
        # Build analysis data
        data_dict = {
            "overall_entropy": overall_entropy,
            "classification": classification,
            "high_entropy_regions": len(high_entropy_regions),
            "entropy_variance": round(entropy_variance, 4),
            "entropy_std": round(entropy_std, 4),
            "file_size": len(data)
        }
        
        if sections_entropy:
            data_dict["sections"] = sections_entropy
            data_dict["suspicious_sections"] = sum(1 for s in sections_entropy if s["suspicious"])
        
        # Build Slack blocks
        blocks = []
        
        # Overall entropy assessment
        threat_level = "🔴 High" if overall_entropy > 7.5 else "🟡 Medium" if overall_entropy > 6.5 else "🟢 Low"
        
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"📊 *Entropy Analysis* {emoji}"},
            "fields": [
                {"type": "mrkdwn", "text": f"*Overall Entropy:*\n{overall_entropy}/8.0"},
                {"type": "mrkdwn", "text": f"*Classification:*\n{classification}"},
                {"type": "mrkdwn", "text": f"*Threat Level:*\n{threat_level}"},
                {"type": "mrkdwn", "text": f"*Variance:*\n{round(entropy_variance, 2)}"}
            ]
        })
        
        # High entropy regions
        if high_entropy_regions:
            blocks.append({"type": "divider"})
            regions_text = f"Found {len(high_entropy_regions)} high-entropy regions (>{self.high_entropy_threshold} bits)"
            
            # Show first few regions
            sample_regions = high_entropy_regions[:3]
            regions_detail = "\n".join([f"• Offset `0x{offset:08x}`: {ent:.3f} bits" for offset, ent in sample_regions])
            
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"⚠️ *High Entropy Regions*\n{regions_text}\n\n{regions_detail}"}
            })
        
        # Section entropy if available
        if sections_entropy:
            blocks.append({"type": "divider"})
            
            # Top suspicious sections
            suspicious = [s for s in sections_entropy if s["suspicious"]][:5]
            if suspicious:
                sus_text = "\n".join([
                    f"• `{s['name']}`: {s['entropy']:.3f} bits"
                    for s in suspicious
                ])
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"🔍 *Suspicious Sections* ({len(suspicious)} found)\n{sus_text}"}
                })
            else:
                # Show top sections by entropy
                top_sections = sections_entropy[:3]
                if top_sections:
                    sec_text = "\n".join([
                        f"• `{s['name']}`: {s['entropy']:.3f} bits"
                        for s in top_sections
                    ])
                    blocks.append({
                        "type": "context",
                        "elements": [{"type": "mrkdwn", "text": f"*Top Sections:*\n{sec_text}"}]
                    })
        
        # Analysis summary
        analysis_notes = []
        if overall_entropy > 7.5:
            analysis_notes.append("🔒 File appears to be encrypted or packed")
        elif overall_entropy > 6.5:
            analysis_notes.append("📦 File appears to be compressed")
        
        if entropy_variance < 0.5 and overall_entropy > 6:
            analysis_notes.append("🎯 Uniform high entropy suggests encryption")
        elif entropy_variance > 2:
            analysis_notes.append("📈 Variable entropy suggests mixed content")
        
        if analysis_notes:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": " • ".join(analysis_notes)}]
            })
        
        return AnalysisResult(
            analyzer_name="Entropy Scanner",
            success=True,
            data=data_dict,
            slack_blocks=blocks
        )