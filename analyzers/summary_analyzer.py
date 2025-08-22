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
            "text": {"type": "plain_text", "text": f"Binary Analysis Report: {file_name}"}
        })
        
        # Introduction
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Analysis Components*\n\nThe following security modules have been applied to analyze this file:"
            }
        })
        
        blocks.append({"type": "divider"})
        
        # Explain each analyzer
        analyzer_explanations = {
            "Hash Calculator": {
                "description": "Generates cryptographic fingerprints (SHA256, MD5, SHA1) that uniquely identify this file",
                "purpose": "File identification and integrity verification"
            },
            "VirusTotal Scanner": {
                "description": "Queries VirusTotal database to check if this file hash has been previously analyzed",
                "purpose": "Detection ratio from 70+ antivirus engines"
            },
            "Heatmap Generator": {
                "description": "Creates a visual representation of byte-pair frequency distribution",
                "purpose": "Pattern recognition and structural analysis"
            },
            "Entropy Scanner": {
                "description": "Calculates Shannon entropy to measure data randomness (scale: 0-8 bits)",
                "purpose": "Detection of encryption, compression, or packing"
            },
            "Headers Inspector": {
                "description": "Parses executable headers to extract structural information",
                "purpose": "Binary format analysis, import/export tables, section mapping"
            },
            "Strings Extractor": {
                "description": "Extracts human-readable ASCII and UTF-16 strings from binary data",
                "purpose": "Identification of embedded text, URLs, file paths, and keywords"
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
                            "text": f"*{analyzer_name}*\n{info['description']}\n_Purpose: {info['purpose']}_"
                        }
                    })
        
        blocks.append({"type": "divider"})
        
        # How to interpret results
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Interpretation Guidelines*"
            }
        })
        
        interpretation_guide = [
            "• *File Paths and URLs:* Verify legitimacy of referenced network endpoints and file system locations",
            "• *Cryptographic Indicators:* Presence of encryption-related terms indicates cryptographic operations or key material",
            "• *Authentication Keywords:* Terms related to passwords and authentication warrant additional scrutiny",
            "• *Entropy Analysis:* Values above 7.5 typically indicate encryption or compression; compare with section-level entropy",
            "• *Binary Structure:* Review imported libraries, exported functions, and section characteristics for anomalies"
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
                    "text": f"Analysis complete. {len(all_results)} modules processed. Detailed results follow below."
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