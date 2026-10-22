"""Extensible framework detection for Android package containers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from .android_artifacts import AndroidArtifact


class AndroidFrameworkDetector(Protocol):
    """A detector that returns evidence without launching the application."""

    framework_id: str

    def inspect(self, artifact: AndroidArtifact) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class DCloudDetector:
    framework_id: str = "uni-app/dcloud"

    def inspect(self, artifact: AndroidArtifact) -> dict[str, Any]:
        return artifact.dcloud_inspect()


@dataclass(frozen=True, slots=True)
class FlutterDetector:
    framework_id: str = "flutter"

    def inspect(self, artifact: AndroidArtifact) -> dict[str, Any]:
        from .flutter_artifacts import FlutterArtifactInspector

        return FlutterArtifactInspector(artifact).inspect()


def builtin_framework_detectors() -> tuple[AndroidFrameworkDetector, ...]:
    return (DCloudDetector(), FlutterDetector())


def detect_android_frameworks(artifact: AndroidArtifact) -> dict[str, Any]:
    """Return all detector results and an evidence-backed primary match."""
    results = []
    for detector in builtin_framework_detectors():
        result = dict(detector.inspect(artifact))
        result.setdefault("framework", detector.framework_id)
        result.setdefault("detected", False)
        results.append(result)

    matches = [result for result in results if result["detected"]]
    primary = matches[0] if matches else None
    return {
        "artifact": str(artifact.path),
        "detected": bool(matches),
        "framework": primary["framework"] if primary else None,
        "frameworks": [result["framework"] for result in matches],
        "matches": matches,
        "detectors": results,
    }
