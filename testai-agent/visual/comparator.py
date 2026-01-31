"""
TestAI Agent - Visual Comparator

Perceptual image comparison with multiple algorithms,
smart region detection, and sensitivity controls.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
import uuid
import math


class ComparisonMethod(Enum):
    """Methods for comparing images."""
    PIXEL_DIFF = "pixel_diff"
    STRUCTURAL = "structural"
    PERCEPTUAL = "perceptual"
    HISTOGRAM = "histogram"
    HYBRID = "hybrid"


class DiffSeverity(Enum):
    """Severity of visual differences."""
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    TRIVIAL = "trivial"


@dataclass
class DiffRegion:
    """A region of visual difference."""
    region_id: str
    x: int
    y: int
    width: int
    height: int
    diff_percentage: float
    severity: DiffSeverity
    description: str = ""
    pixel_count: int = 0


@dataclass
class ComparisonResult:
    """Result of visual comparison."""
    result_id: str
    baseline_id: str
    current_id: str
    method: ComparisonMethod
    match_percentage: float
    diff_percentage: float
    diff_regions: List[DiffRegion]
    passed: bool
    threshold: float
    compared_at: datetime
    duration_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ImageData:
    """Simulated image data for comparison."""
    image_id: str
    width: int
    height: int
    pixels: List[List[Tuple[int, int, int]]]  # RGB values
    checksum: str
    captured_at: datetime


class VisualComparator:
    """
    Visual comparison engine for regression testing.

    Features:
    - Multiple comparison algorithms
    - Smart region detection
    - Configurable thresholds
    - Anti-aliasing tolerance
    - Ignore regions
    """

    # Default thresholds
    DEFAULT_THRESHOLD = 0.99  # 99% match required
    ANTI_ALIASING_TOLERANCE = 2  # Pixel color tolerance

    # Severity thresholds
    SEVERITY_THRESHOLDS = {
        DiffSeverity.CRITICAL: 0.10,  # >10% diff
        DiffSeverity.MAJOR: 0.05,     # 5-10% diff
        DiffSeverity.MINOR: 0.01,     # 1-5% diff
        DiffSeverity.TRIVIAL: 0.0,    # <1% diff
    }

    def __init__(
        self,
        default_method: ComparisonMethod = ComparisonMethod.PERCEPTUAL,
        threshold: float = 0.99,
        anti_aliasing_tolerance: int = 2,
    ):
        """Initialize the comparator."""
        self._default_method = default_method
        self._threshold = threshold
        self._aa_tolerance = anti_aliasing_tolerance

        self._ignore_regions: Dict[str, List[Tuple[int, int, int, int]]] = {}
        self._baselines: Dict[str, ImageData] = {}
        self._results: List[ComparisonResult] = []

        self._result_counter = 0

    def set_baseline(
        self,
        baseline_id: str,
        width: int,
        height: int,
        pixels: Optional[List[List[Tuple[int, int, int]]]] = None,
    ) -> ImageData:
        """Set a baseline image for comparison."""
        if pixels is None:
            # Generate default white pixels
            pixels = [[(255, 255, 255) for _ in range(width)] for _ in range(height)]

        checksum = self._calculate_checksum(pixels)

        image = ImageData(
            image_id=baseline_id,
            width=width,
            height=height,
            pixels=pixels,
            checksum=checksum,
            captured_at=datetime.now(),
        )

        self._baselines[baseline_id] = image
        return image

    def add_ignore_region(
        self,
        baseline_id: str,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> None:
        """Add a region to ignore during comparison."""
        if baseline_id not in self._ignore_regions:
            self._ignore_regions[baseline_id] = []

        self._ignore_regions[baseline_id].append((x, y, width, height))

    def compare(
        self,
        baseline_id: str,
        current_width: int,
        current_height: int,
        current_pixels: Optional[List[List[Tuple[int, int, int]]]] = None,
        method: Optional[ComparisonMethod] = None,
        threshold: Optional[float] = None,
    ) -> ComparisonResult:
        """Compare current image against baseline."""
        self._result_counter += 1
        result_id = f"VCR-{self._result_counter:05d}"

        start_time = datetime.now()
        method = method or self._default_method
        threshold = threshold or self._threshold

        baseline = self._baselines.get(baseline_id)
        if not baseline:
            # Create a baseline if not exists
            baseline = self.set_baseline(baseline_id, current_width, current_height)

        if current_pixels is None:
            # Generate white pixels for current
            current_pixels = [
                [(255, 255, 255) for _ in range(current_width)]
                for _ in range(current_height)
            ]

        current_id = f"current-{uuid.uuid4().hex[:8]}"

        # Perform comparison based on method
        if method == ComparisonMethod.PIXEL_DIFF:
            match_pct, diff_regions = self._pixel_diff(
                baseline.pixels, current_pixels, baseline_id
            )
        elif method == ComparisonMethod.STRUCTURAL:
            match_pct, diff_regions = self._structural_diff(
                baseline.pixels, current_pixels, baseline_id
            )
        elif method == ComparisonMethod.PERCEPTUAL:
            match_pct, diff_regions = self._perceptual_diff(
                baseline.pixels, current_pixels, baseline_id
            )
        elif method == ComparisonMethod.HISTOGRAM:
            match_pct, diff_regions = self._histogram_diff(
                baseline.pixels, current_pixels, baseline_id
            )
        else:  # HYBRID
            match_pct, diff_regions = self._hybrid_diff(
                baseline.pixels, current_pixels, baseline_id
            )

        end_time = datetime.now()
        duration_ms = (end_time - start_time).total_seconds() * 1000

        passed = match_pct >= threshold

        result = ComparisonResult(
            result_id=result_id,
            baseline_id=baseline_id,
            current_id=current_id,
            method=method,
            match_percentage=match_pct,
            diff_percentage=1 - match_pct,
            diff_regions=diff_regions,
            passed=passed,
            threshold=threshold,
            compared_at=datetime.now(),
            duration_ms=duration_ms,
        )

        self._results.append(result)
        return result

    def _calculate_checksum(
        self,
        pixels: List[List[Tuple[int, int, int]]],
    ) -> str:
        """Calculate a simple checksum for pixels."""
        total = 0
        for row in pixels:
            for r, g, b in row:
                total += r + g + b

        return f"chk-{total % 1000000:06d}"

    def _is_in_ignore_region(
        self,
        baseline_id: str,
        x: int,
        y: int,
    ) -> bool:
        """Check if a pixel is in an ignore region."""
        regions = self._ignore_regions.get(baseline_id, [])
        for rx, ry, rw, rh in regions:
            if rx <= x < rx + rw and ry <= y < ry + rh:
                return True
        return False

    def _pixel_diff(
        self,
        baseline: List[List[Tuple[int, int, int]]],
        current: List[List[Tuple[int, int, int]]],
        baseline_id: str,
    ) -> Tuple[float, List[DiffRegion]]:
        """Pixel-by-pixel comparison."""
        height = min(len(baseline), len(current))
        width = min(len(baseline[0]) if baseline else 0, len(current[0]) if current else 0)

        if width == 0 or height == 0:
            return 0.0, []

        diff_pixels = []
        total_pixels = width * height

        for y in range(height):
            for x in range(width):
                if self._is_in_ignore_region(baseline_id, x, y):
                    continue

                br, bg, bb = baseline[y][x]
                cr, cg, cb = current[y][x]

                # Check with anti-aliasing tolerance
                if (
                    abs(br - cr) > self._aa_tolerance or
                    abs(bg - cg) > self._aa_tolerance or
                    abs(bb - cb) > self._aa_tolerance
                ):
                    diff_pixels.append((x, y))

        match_pct = 1 - (len(diff_pixels) / total_pixels) if total_pixels > 0 else 1.0
        diff_regions = self._cluster_diff_pixels(diff_pixels)

        return match_pct, diff_regions

    def _structural_diff(
        self,
        baseline: List[List[Tuple[int, int, int]]],
        current: List[List[Tuple[int, int, int]]],
        baseline_id: str,
    ) -> Tuple[float, List[DiffRegion]]:
        """Structural similarity comparison (simplified SSIM)."""
        # Simplified SSIM implementation
        match_pct, diff_regions = self._pixel_diff(baseline, current, baseline_id)

        # Apply structural weight (nearby pixels matter)
        # Simplified: just use pixel diff with slight adjustment
        structural_match = match_pct * 0.9 + 0.1  # Slightly more lenient

        return structural_match, diff_regions

    def _perceptual_diff(
        self,
        baseline: List[List[Tuple[int, int, int]]],
        current: List[List[Tuple[int, int, int]]],
        baseline_id: str,
    ) -> Tuple[float, List[DiffRegion]]:
        """Perceptual comparison (considers human vision)."""
        height = min(len(baseline), len(current))
        width = min(len(baseline[0]) if baseline else 0, len(current[0]) if current else 0)

        if width == 0 or height == 0:
            return 0.0, []

        diff_pixels = []
        total_pixels = width * height

        for y in range(height):
            for x in range(width):
                if self._is_in_ignore_region(baseline_id, x, y):
                    continue

                # Convert to luminance for perceptual comparison
                bl = self._to_luminance(*baseline[y][x])
                cl = self._to_luminance(*current[y][x])

                # Perceptual difference threshold
                if abs(bl - cl) > 10:  # Higher tolerance for perceptual
                    diff_pixels.append((x, y))

        match_pct = 1 - (len(diff_pixels) / total_pixels) if total_pixels > 0 else 1.0
        diff_regions = self._cluster_diff_pixels(diff_pixels)

        return match_pct, diff_regions

    def _histogram_diff(
        self,
        baseline: List[List[Tuple[int, int, int]]],
        current: List[List[Tuple[int, int, int]]],
        baseline_id: str,
    ) -> Tuple[float, List[DiffRegion]]:
        """Histogram-based comparison."""
        # Build histograms
        baseline_hist = [0] * 256
        current_hist = [0] * 256

        for row in baseline:
            for r, g, b in row:
                lum = int(self._to_luminance(r, g, b))
                baseline_hist[min(255, lum)] += 1

        for row in current:
            for r, g, b in row:
                lum = int(self._to_luminance(r, g, b))
                current_hist[min(255, lum)] += 1

        # Compare histograms
        total = sum(baseline_hist) + sum(current_hist)
        if total == 0:
            return 1.0, []

        diff = sum(abs(b - c) for b, c in zip(baseline_hist, current_hist))
        match_pct = 1 - (diff / total)

        # No specific regions for histogram comparison
        return match_pct, []

    def _hybrid_diff(
        self,
        baseline: List[List[Tuple[int, int, int]]],
        current: List[List[Tuple[int, int, int]]],
        baseline_id: str,
    ) -> Tuple[float, List[DiffRegion]]:
        """Hybrid comparison using multiple methods."""
        pixel_match, pixel_regions = self._pixel_diff(baseline, current, baseline_id)
        perceptual_match, _ = self._perceptual_diff(baseline, current, baseline_id)
        histogram_match, _ = self._histogram_diff(baseline, current, baseline_id)

        # Weighted average
        hybrid_match = (
            pixel_match * 0.4 +
            perceptual_match * 0.4 +
            histogram_match * 0.2
        )

        return hybrid_match, pixel_regions

    def _to_luminance(self, r: int, g: int, b: int) -> float:
        """Convert RGB to luminance."""
        return 0.299 * r + 0.587 * g + 0.114 * b

    def _cluster_diff_pixels(
        self,
        diff_pixels: List[Tuple[int, int]],
    ) -> List[DiffRegion]:
        """Cluster diff pixels into regions."""
        if not diff_pixels:
            return []

        # Simple grid-based clustering
        grid_size = 50
        grid_cells: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}

        for x, y in diff_pixels:
            cell = (x // grid_size, y // grid_size)
            if cell not in grid_cells:
                grid_cells[cell] = []
            grid_cells[cell].append((x, y))

        regions = []
        for cell, pixels in grid_cells.items():
            if not pixels:
                continue

            min_x = min(p[0] for p in pixels)
            max_x = max(p[0] for p in pixels)
            min_y = min(p[1] for p in pixels)
            max_y = max(p[1] for p in pixels)

            width = max_x - min_x + 1
            height = max_y - min_y + 1
            area = width * height
            diff_pct = len(pixels) / area if area > 0 else 0

            severity = self._determine_severity(diff_pct)

            regions.append(DiffRegion(
                region_id=f"DR-{uuid.uuid4().hex[:6]}",
                x=min_x,
                y=min_y,
                width=width,
                height=height,
                diff_percentage=diff_pct,
                severity=severity,
                description=f"{len(pixels)} pixels differ",
                pixel_count=len(pixels),
            ))

        return regions

    def _determine_severity(self, diff_pct: float) -> DiffSeverity:
        """Determine severity based on diff percentage."""
        if diff_pct >= self.SEVERITY_THRESHOLDS[DiffSeverity.CRITICAL]:
            return DiffSeverity.CRITICAL
        elif diff_pct >= self.SEVERITY_THRESHOLDS[DiffSeverity.MAJOR]:
            return DiffSeverity.MAJOR
        elif diff_pct >= self.SEVERITY_THRESHOLDS[DiffSeverity.MINOR]:
            return DiffSeverity.MINOR
        else:
            return DiffSeverity.TRIVIAL

    def get_comparison_history(
        self,
        baseline_id: str,
        limit: int = 10,
    ) -> List[ComparisonResult]:
        """Get comparison history for a baseline."""
        results = [r for r in self._results if r.baseline_id == baseline_id]
        return results[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get comparator statistics."""
        if not self._results:
            return {
                "total_comparisons": 0,
                "baselines": len(self._baselines),
                "avg_match_percentage": 0,
                "pass_rate": 0,
            }

        return {
            "total_comparisons": len(self._results),
            "baselines": len(self._baselines),
            "avg_match_percentage": sum(r.match_percentage for r in self._results) / len(self._results),
            "pass_rate": sum(1 for r in self._results if r.passed) / len(self._results),
        }

    def format_result(self, result: ComparisonResult) -> str:
        """Format a comparison result for display."""
        status = "✅ PASSED" if result.passed else "❌ FAILED"

        severity_emoji = {
            DiffSeverity.CRITICAL: "🔴",
            DiffSeverity.MAJOR: "🟠",
            DiffSeverity.MINOR: "🟡",
            DiffSeverity.TRIVIAL: "🟢",
        }

        lines = [
            "=" * 60,
            f"  {status} VISUAL COMPARISON",
            "=" * 60,
            "",
            f"  Baseline: {result.baseline_id}",
            f"  Method: {result.method.value}",
            "",
            f"  Match: {result.match_percentage:.1%}",
            f"  Threshold: {result.threshold:.1%}",
            f"  Duration: {result.duration_ms:.0f}ms",
            "",
        ]

        if result.diff_regions:
            lines.append("-" * 60)
            lines.append(f"  DIFF REGIONS ({len(result.diff_regions)})")
            lines.append("-" * 60)

            for region in result.diff_regions[:5]:
                lines.append(
                    f"  {severity_emoji[region.severity]} "
                    f"({region.x}, {region.y}) {region.width}x{region.height} "
                    f"- {region.diff_percentage:.1%} diff"
                )

            if len(result.diff_regions) > 5:
                lines.append(f"  ... and {len(result.diff_regions) - 5} more")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_visual_comparator(
    default_method: ComparisonMethod = ComparisonMethod.PERCEPTUAL,
    threshold: float = 0.99,
    anti_aliasing_tolerance: int = 2,
) -> VisualComparator:
    """Create a visual comparator instance."""
    return VisualComparator(
        default_method=default_method,
        threshold=threshold,
        anti_aliasing_tolerance=anti_aliasing_tolerance,
    )
