"""
Summary analyzer that provides educational overview of analysis modules
"""
from typing import Dict, List, Optional
from .base import BaseAnalyzer, AnalysisResult

class SummaryAnalyzer(BaseAnalyzer):
    """Generate educational summary explaining what each analyzer does"""
    
    def analyze(self, file_path: str, all_results: Optional[List[AnalysisResult]] = None, **kwargs) -> AnalysisResult:
        """Generate educational summary explaining the analysis"""
        
        # Get file info
        file_name = file_path.split("/")[-1] if "/" in file_path else file_path
        
        # Build educational summary blocks
        blocks = []
        
        # Header
        blocks.append({
            "type": "header",
            "text": {"type": "plain_text", "text": f"📋 Analysis Guide for {file_name}"}
        })
        
        # Introduction
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Understanding Your Analysis Results*\n\nThis file has been analyzed by multiple security modules. Here's what each section means:"
            }
        })
        
        blocks.append({"type": "divider"})
        
        # Explain each analyzer
        analyzer_explanations = {
            "Hash Calculator": {
                "emoji": "🔐",
                "description": "Cryptographic fingerprints that uniquely identify this file",
                "what_to_look_for": "Use these hashes to check if the file matches known samples or to track file modifications"
            },
            "VirusTotal Scanner": {
                "emoji": "🛡️",
                "description": "Cross-references the file against 70+ antivirus engines",
                "what_to_look_for": "Detection ratio shows how many engines flagged the file as malicious"
            },
            "Heatmap Generator": {
                "emoji": "🗺️",
                "description": "Visual fingerprint showing byte-pair frequency patterns",
                "what_to_look_for": "Dark areas indicate unused byte combinations, bright spots show common patterns, diagonal lines suggest sequential data"
            },
            "Entropy Scanner": {
                "emoji": "📊",
                "description": "Measures randomness in the file (0-8 scale)",
                "what_to_look_for": "High entropy (>7.5) suggests encryption/packing, low entropy (<3) indicates text/structured data"
            },
            "Headers Inspector": {
                "emoji": "📦",
                "description": "Analyzes binary structure (PE/ELF/Mach-O)",
                "what_to_look_for": "Imports show external functions used, sections reveal code organization, security features indicate exploit mitigations"
            },
            "Strings Extractor": {
                "emoji": "🔤",
                "description": "Extracts readable text from the binary",
                "what_to_look_for": "URLs may indicate network activity, paths reveal file operations, suspicious keywords suggest malicious behavior"
            }
        }
        
        # Add explanation for each analyzer that was run
        if all_results:
            for result in all_results:
                analyzer_name = result.analyzer_name
                # Clean up analyzer names
                if "Headers Inspector" in analyzer_name:
                    analyzer_name = "Headers Inspector"
                elif "Entropy Scanner" in analyzer_name:
                    analyzer_name = "Entropy Scanner"
                elif "Strings Extractor" in analyzer_name:
                    analyzer_name = "Strings Extractor"
                
                if analyzer_name in analyzer_explanations:
                    info = analyzer_explanations[analyzer_name]
                    blocks.append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{info['emoji']} *{analyzer_name}*\n_{info['description']}_"
                        }
                    })
                    blocks.append({
                        "type": "context",
                        "elements": [{
                            "type": "mrkdwn",
                            "text": f"💡 *What to look for:* {info['what_to_look_for']}"
                        }]
                    })
        
        blocks.append({"type": "divider"})
        
        # How to interpret results
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*📖 Reading the Results*"
            }
        })
        
        interpretation_guide = [
            "• **Paths & URLs**: Check if they point to legitimate services or suspicious domains",
            "• **Crypto Indicators**: Terms like 'privatekey', 'SSL', 'cipher' show cryptographic operations",
            "• **Suspicious Strings**: Keywords like 'password', 'authentication', 'download' may indicate sensitive operations",
            "• **Entropy Levels**: Compare file entropy with section entropy to spot packed/encrypted regions",
            "• **Binary Headers**: Look for unusual imports, missing security features, or suspicious section names"
        ]
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "\n".join(interpretation_guide)
            }
        })
        
        # Footer with module count
        if all_results:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"✅ Analysis complete • {len(all_results)} modules processed • Review each section below for details"
                }]
            })
        
        return AnalysisResult(
            analyzer_name="Analysis Guide",
            success=True,
            data={
                "file_name": file_name,
                "modules_run": len(all_results) if all_results else 0
            },
            slack_blocks=blocks
        )