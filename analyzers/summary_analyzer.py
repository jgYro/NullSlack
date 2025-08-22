"""
Summary analyzer that provides executive summary and risk assessment
"""
from typing import Dict, List, Optional
from .base import BaseAnalyzer, AnalysisResult

class SummaryAnalyzer(BaseAnalyzer):
    """Generate executive summary and risk assessment"""
    
    def analyze_risk_indicators(self, all_results: List[AnalysisResult]) -> Dict:
        """Analyze all results to determine risk indicators"""
        indicators = {
            "high_risk": [],
            "medium_risk": [],
            "low_risk": [],
            "info": []
        }
        
        # Check VirusTotal results
        for result in all_results:
            if result.analyzer_name == "VirusTotal Scanner" and result.success:
                data = result.data
                if data.get("found"):
                    malicious = data.get("malicious", 0)
                    if malicious > 5:
                        indicators["high_risk"].append(f"🚨 {malicious} antivirus engines detected malware")
                    elif malicious > 0:
                        indicators["medium_risk"].append(f"⚠️ {malicious} antivirus engines flagged as suspicious")
                else:
                    indicators["info"].append("📝 File not previously analyzed by VirusTotal")
        
        # Check entropy results
        for result in all_results:
            if result.analyzer_name == "Entropy Scanner" and result.success:
                data = result.data
                entropy = data.get("overall_entropy", 0)
                if entropy > 7.8:
                    indicators["high_risk"].append("🔒 Very high entropy suggests encryption/packing")
                elif entropy > 7.2:
                    indicators["medium_risk"].append("📦 High entropy indicates compression/obfuscation")
                
                suspicious_sections = data.get("suspicious_sections", 0)
                if suspicious_sections > 3:
                    indicators["medium_risk"].append(f"🔍 {suspicious_sections} sections with suspicious entropy")
        
        # Check strings results
        for result in all_results:
            if result.analyzer_name == "Strings Extractor" and result.success:
                data = result.data
                interesting = data.get("interesting", {})
                
                if len(interesting.get("suspicious", [])) > 10:
                    indicators["high_risk"].append(f"⚠️ {len(interesting['suspicious'])} suspicious strings detected")
                elif len(interesting.get("suspicious", [])) > 5:
                    indicators["medium_risk"].append(f"⚠️ {len(interesting['suspicious'])} potentially suspicious strings")
                
                if interesting.get("ips", []):
                    indicators["medium_risk"].append(f"🔢 Contains {len(interesting['ips'])} IP addresses")
                
                if interesting.get("urls", []):
                    indicators["info"].append(f"🌐 Contains {len(interesting['urls'])} URLs")
        
        # Check headers results
        for result in all_results:
            if "Headers Inspector" in result.analyzer_name and result.success:
                data = result.data
                
                # Check for suspicious sections/imports
                if data.get("suspicious_sections"):
                    indicators["medium_risk"].append(f"📦 Suspicious sections: {', '.join(data['suspicious_sections'][:3])}")
                
                if data.get("suspicious_imports"):
                    indicators["medium_risk"].append(f"📚 Suspicious imports detected")
                
                # Check security features
                if data.get("dll_characteristics"):
                    has_aslr = "DYNAMIC_BASE" in data["dll_characteristics"]
                    has_dep = "NX_COMPAT" in data["dll_characteristics"]
                    if not has_aslr and not has_dep:
                        indicators["low_risk"].append("🛡️ Missing modern security features")
                
                if data.get("security"):
                    sec = data["security"]
                    if not sec.get("nx") and not sec.get("pie"):
                        indicators["low_risk"].append("🛡️ No exploit mitigation features enabled")
        
        return indicators
    
    def generate_risk_score(self, indicators: Dict) -> tuple:
        """Calculate overall risk score and level"""
        score = 0
        score += len(indicators["high_risk"]) * 30
        score += len(indicators["medium_risk"]) * 15
        score += len(indicators["low_risk"]) * 5
        
        if score >= 60:
            return score, "HIGH", "🔴"
        elif score >= 30:
            return score, "MEDIUM", "🟡"
        elif score >= 10:
            return score, "LOW", "🟢"
        else:
            return score, "MINIMAL", "⚪"
    
    def generate_recommendation(self, risk_level: str, indicators: Dict) -> str:
        """Generate actionable recommendation based on risk"""
        if risk_level == "HIGH":
            return "🚨 *Immediate Action Required:* This file shows multiple high-risk indicators. Do not execute. Consider quarantine and deeper analysis."
        elif risk_level == "MEDIUM":
            return "⚠️ *Caution Advised:* This file has suspicious characteristics. Verify source and scan with additional tools before use."
        elif risk_level == "LOW":
            return "🟢 *Low Risk:* File appears relatively safe but maintain standard precautions."
        else:
            return "⚪ *Minimal Risk:* No significant threats detected. Standard security practices apply."
    
    def analyze(self, file_path: str, all_results: Optional[List[AnalysisResult]] = None, **kwargs) -> AnalysisResult:
        """Generate executive summary from all analysis results"""
        
        if not all_results:
            # Can't generate summary without other results
            return AnalysisResult(
                analyzer_name="Executive Summary",
                success=False,
                error="No analysis results available for summary"
            )
        
        # Get file info
        file_name = file_path.split("/")[-1] if "/" in file_path else file_path
        
        # Analyze risk indicators
        indicators = self.analyze_risk_indicators(all_results)
        risk_score, risk_level, risk_emoji = self.generate_risk_score(indicators)
        recommendation = self.generate_recommendation(risk_level, indicators)
        
        # Build summary blocks
        blocks = []
        
        # Header with risk level
        blocks.append({
            "type": "header",
            "text": {"type": "plain_text", "text": f"{risk_emoji} Executive Summary: {risk_level} RISK"}
        })
        
        # What does this mean section
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🎯 What This Means To You:*\n" + recommendation
            }
        })
        
        # Key findings
        if any(indicators.values()):
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*🔍 Key Findings:*"}
            })
            
            # High risk indicators
            if indicators["high_risk"]:
                findings_text = "\n".join(indicators["high_risk"][:3])
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Critical Issues:*\n{findings_text}"}
                })
            
            # Medium risk indicators
            if indicators["medium_risk"]:
                findings_text = "\n".join(indicators["medium_risk"][:3])
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Warnings:*\n{findings_text}"}
                })
            
            # Low risk indicators
            if indicators["low_risk"] and not indicators["high_risk"]:
                findings_text = "\n".join(indicators["low_risk"][:2])
                blocks.append({
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"*Minor Issues:* {findings_text}"}]
                })
        
        # Quick stats
        total_issues = sum(len(v) for v in indicators.values())
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Risk Score: {risk_score} | Total Issues: {total_issues} | Modules Run: {len(all_results)}"}
            ]
        })
        
        return AnalysisResult(
            analyzer_name="Executive Summary",
            success=True,
            data={
                "risk_level": risk_level,
                "risk_score": risk_score,
                "indicators": indicators,
                "recommendation": recommendation
            },
            slack_blocks=blocks
        )