"""
Byte-pair heatmap analyzer
Generates visual fingerprint of binary structure
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm
from typing import Dict, Tuple, Optional
from .base import BaseAnalyzer, AnalysisResult

class HeatmapAnalyzer(BaseAnalyzer):
    """Generate byte-pair frequency heatmaps"""
    
    def __init__(self, bins: int = 256, figsize: Tuple[int, int] = (8, 8), dpi: int = 100):
        super().__init__()
        self.bins = bins
        self.figsize = figsize
        self.dpi = dpi
    
    def generate_heatmap(self, file_path: str, output_path: str) -> Dict:
        """
        Generate 2D histogram of consecutive byte pairs (b[i], b[i+1])
        Returns metrics about the file structure
        """
        # Read file data
        data = np.fromfile(file_path, dtype=np.uint8)
        
        # Calculate byte-pair frequencies
        if data.size >= 2:
            pairs = np.lib.stride_tricks.sliding_window_view(data, 2)
            x = pairs[:, 0].astype(np.int32)
            y = pairs[:, 1].astype(np.int32)
            hist, _, _ = np.histogram2d(x, y, bins=self.bins, range=[[0, 255], [0, 255]])
        else:
            hist = np.zeros((self.bins, self.bins), dtype=np.float64)
        
        # Create visualization
        plt.figure(figsize=self.figsize, dpi=self.dpi)
        plt.imshow(
            hist.T + 1.0,  # Add 1 to avoid log(0)
            origin="lower",
            cmap="inferno",
            norm=LogNorm(),
            extent=[0, 255, 0, 255],
            interpolation="nearest",
            aspect="equal",
        )
        plt.title("Byte-Pair Heatmap (log scale)", fontsize=14)
        plt.xlabel("byte[i]", fontsize=12)
        plt.ylabel("byte[i+1]", fontsize=12)
        plt.colorbar(label="Frequency (log scale)")
        plt.tight_layout()
        plt.savefig(output_path, format="png", bbox_inches="tight", dpi=self.dpi)
        plt.close()
        
        # Calculate metrics
        metrics = {
            "total_bytes": int(data.size),
            "unique_bytes": int(len(np.unique(data))) if data.size else 0,
            "byte_entropy": self.calculate_byte_entropy(data),
            "pair_entropy": self.calculate_pair_entropy(hist),
            "diagonal_strength": self.calculate_diagonal_strength(hist),
            "clustering_coefficient": self.calculate_clustering(hist)
        }
        
        return metrics
    
    def calculate_byte_entropy(self, data: np.ndarray) -> float:
        """Calculate Shannon entropy of individual bytes"""
        if data.size == 0:
            return 0.0
        unique, counts = np.unique(data, return_counts=True)
        probs = counts / data.size
        entropy = -np.sum(probs * np.log2(probs + 1e-10))
        return round(entropy, 3)
    
    def calculate_pair_entropy(self, hist: np.ndarray) -> float:
        """Calculate entropy of byte pair distribution"""
        total = hist.sum()
        if total == 0:
            return 0.0
        probs = hist.flatten() / total
        probs = probs[probs > 0]
        entropy = -np.sum(probs * np.log2(probs))
        return round(entropy, 3)
    
    def calculate_diagonal_strength(self, hist: np.ndarray) -> float:
        """Calculate strength of diagonal patterns (sequential bytes)"""
        if hist.sum() == 0:
            return 0.0
        diagonal_sum = np.trace(hist)
        off_diagonal_sum = np.trace(hist, offset=1) + np.trace(hist, offset=-1)
        total_sum = hist.sum()
        diagonal_ratio = (diagonal_sum + off_diagonal_sum * 0.5) / total_sum
        return round(diagonal_ratio, 3)
    
    def calculate_clustering(self, hist: np.ndarray) -> float:
        """Calculate clustering coefficient (how concentrated the heatmap is)"""
        if hist.sum() == 0:
            return 0.0
        # Find the top 10% of values
        threshold = np.percentile(hist[hist > 0], 90) if np.any(hist > 0) else 0
        clustered = hist > threshold
        clustering = clustered.sum() / (hist.size + 1e-10)
        return round(clustering, 3)
    
    def classify_pattern(self, metrics: Dict) -> Tuple[str, str]:
        """Classify the heatmap pattern based on metrics"""
        diagonal = metrics.get("diagonal_strength", 0)
        clustering = metrics.get("clustering_coefficient", 0)
        pair_entropy = metrics.get("pair_entropy", 0)
        
        if pair_entropy > 15:
            return "Random/Encrypted", "🔒"
        elif diagonal > 0.1:
            return "Sequential/Text", "📝"
        elif clustering > 0.05:
            return "Structured Binary", "📊"
        elif pair_entropy < 10:
            return "Repetitive/Padding", "🔁"
        else:
            return "Mixed Content", "🔀"
    
    def analyze(self, file_path: str, output_dir: Optional[str] = "/tmp", **kwargs) -> AnalysisResult:
        """Generate heatmap and analyze byte-pair patterns"""
        # Generate output path
        import hashlib
        file_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
        output_path = os.path.join(output_dir, f"heatmap_{file_hash}.png")
        
        # Generate heatmap and get metrics
        metrics = self.generate_heatmap(file_path, output_path)
        pattern_type, pattern_emoji = self.classify_pattern(metrics)
        
        # Add classification to metrics
        metrics["pattern_type"] = pattern_type
        metrics["output_path"] = output_path
        
        # Build Slack blocks
        blocks = [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"🗺️ *Byte-Pair Heatmap Analysis* {pattern_emoji}"},
            "fields": [
                {"type": "mrkdwn", "text": f"*Pattern:*\n{pattern_type}"},
                {"type": "mrkdwn", "text": f"*Unique Bytes:*\n{metrics['unique_bytes']}/256"},
                {"type": "mrkdwn", "text": f"*Byte Entropy:*\n{metrics['byte_entropy']}/8.0"},
                {"type": "mrkdwn", "text": f"*Pair Entropy:*\n{metrics['pair_entropy']:.1f}"}
            ]
        }]
        
        # Add pattern-specific insights
        insights = []
        if metrics["diagonal_strength"] > 0.1:
            insights.append("📈 Strong sequential patterns detected")
        if metrics["clustering_coefficient"] > 0.05:
            insights.append("🎯 Highly concentrated byte pairs")
        if metrics["byte_entropy"] > 7.5:
            insights.append("🔐 High entropy suggests encryption/compression")
        if metrics["unique_bytes"] < 50:
            insights.append("📉 Limited byte diversity")
        
        if insights:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": " • ".join(insights)}]
            })
        
        return AnalysisResult(
            analyzer_name="Heatmap Generator",
            success=True,
            data=metrics,
            slack_blocks=blocks
        )