"""
Base classes for modular analyzers
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

@dataclass
class AnalysisResult:
    """Standardized result format for all analyzers"""
    analyzer_name: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    slack_blocks: List[Dict] = field(default_factory=list)
    
    def to_slack_blocks(self) -> List[Dict]:
        """Generate Slack blocks for this result"""
        if self.slack_blocks:
            return self.slack_blocks
            
        if not self.success:
            return [{
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"⚠️ *{self.analyzer_name} Failed*\n{self.error}"}
            }]
        
        # Default block representation
        fields = []
        for key, value in self.data.items():
            if isinstance(value, list):
                value = f"{len(value)} items"
            fields.append({"type": "mrkdwn", "text": f"*{key}:*\n{value}"})
        
        return [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{self.analyzer_name} Results*"},
            "fields": fields[:10]  # Slack limits fields
        }]

class BaseAnalyzer(ABC):
    """Base class for all analyzers"""
    
    def __init__(self):
        self.name = self.__class__.__name__
    
    @abstractmethod
    def analyze(self, file_path: str, **kwargs) -> AnalysisResult:
        """Perform analysis on the file"""
        pass
    
    def safe_analyze(self, file_path: str, **kwargs) -> AnalysisResult:
        """Wrapper with error handling"""
        try:
            return self.analyze(file_path, **kwargs)
        except Exception as e:
            return AnalysisResult(
                analyzer_name=self.name,
                success=False,
                error=str(e)
            )