from __future__ import annotations

import asyncio
import io
import zipfile
from pathlib import Path

import pytest

from reversing_mcp.android_artifacts import AndroidArtifact
from reversing_mcp.dart_aot import AotAnalyzer, BlutterAnalyzer, FlutterAnalysisCache
from reversing_mcp.errors import ReversingMcpError
from reversing_mcp.flutter_artifacts import FlutterArtifactInspector
from reversing_mcp.models import LifecycleAction, SessionRequest
from reversing_mcp.providers.flutter import FlutterBackend


def run(coroutine):
    return asyncio.run(coroutine)


def archive_bytes(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for path, data in entries.items():
            archive.writestr(path, data)
    return output.getvalue()


def make_flutter_xapk(tmp_path: Path, *, abi: str = "arm64-v8a") -> Path:
    base = archive_bytes(
        {
            "AndroidManifest.xml": b"binary manifest",
            "classes.dex": (
                b"dex\nLio/flutter/plugins/bluetooth/GeneratedPlugin;\x00"
                b"plugins.flutter.io/example\x00"
            ),
            "assets/flutter_assets/AssetManifest.json": (
                b'{"assets/config.json":["assets/config.json"]}'
            ),
            "assets/flutter_assets/assets/config.json": b'{"feature":"battery"}',
        }
    )
    native = archive_bytes(
        {
            f"lib/{abi}/libapp.so": b"\x7fELFplugins.flutter.io/battery",
            f"lib/{abi}/libflutter.so": b"\x7fELFflutter-engine",
            f"lib/{abi}/libble_plugin.so": b"\x7fELFplugin",
        }
    )
    path = tmp_path / "sample.xapk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", b'{"name":"sample"}')
        archive.writestr("base.apk", base)
        archive.writestr(f"config.{abi}.apk", native)
    return path


class FakeAnalyzer(AotAnalyzer):
    analyzer_id = "fake-aot"
    supported_abis = frozenset({"arm64-v8a"})

    def __init__(self) -> None:
        self.calls = 0

    @property
    def identity(self) -> str:
        return "fake-aot:test-v1"

    def analyze(
        self,
        *,
        libapp_path: str,
        libflutter_path: str | None,
        abi: str,
        output_directory: str,
        timeout: float,
    ) -> dict:
        assert Path(libapp_path).read_bytes().startswith(b"\x7fELF")
        assert libflutter_path and Path(libflutter_path).is_file()
        assert abi == "arm64-v8a"
        assert timeout > 0
        self.calls += 1
        output = Path(output_directory)
        (output / "asm").mkdir(parents=True)
        (output / "asm" / "app.dart").write_text(
            "// package:app/main.dart\n"
            "class _App {\n"
            "  void main(/* No info */) {\n"
            "    // 0x1000: ret\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        (output / "objs.txt").write_text(
            "Object pool string: batteryVoltage\n", encoding="utf-8"
        )
        (output / "pp.txt").write_text(
            "Library package:app/main.dart\n", encoding="utf-8"
        )
        return {"returncode": 0, "stdout": "ok", "stderr": ""}


def test_framework_registry_detects_flutter_split_package(tmp_path):
    artifact = AndroidArtifact(str(make_flutter_xapk(tmp_path)))
    try:
        detected = artifact.frameworks_detect()
        flutter = next(
            row for row in detected["matches"] if row["framework"] == "flutter"
        )
        inspector = FlutterArtifactInspector(artifact)
        variants = inspector.variants()["variants"]
        plugins = inspector.plugins({})["plugins"]
        channels = inspector.channels({"query": "plugins.flutter.io"})["channels"]
    finally:
        artifact.close()

    assert detected["frameworks"] == ["flutter"]
    assert flutter["build_mode"] == "release-or-profile-aot"
    assert variants[0]["abi"] == "arm64-v8a"
    assert variants[0]["complete"] is True
    assert plugins[0]["confidence"] == "candidate"
    assert any(row["name"] == "plugins.flutter.io/example" for row in channels)


def test_flutter_provider_baseline_assets_and_target_info(tmp_path):
    path = make_flutter_xapk(tmp_path)
    session = run(
        FlutterBackend(cache=FlutterAnalysisCache(tmp_path / "cache")).open(
            SessionRequest(lifecycle=LifecycleAction.OPEN, target_path=str(path))
        )
    )
    try:
        info = run(session.invoke("target.info", {}))
        assets = run(session.invoke("flutter.assets.list", {"suffix": ".json"}))
        search = run(session.invoke("flutter.assets.search", {"query": "battery"}))
    finally:
        run(session.close())

    assert info["flutter"]["detected"] is True
    assert len(info["sha256"]) == 64
    assert {row["relative_path"] for row in assets["assets"]} == {
        "AssetManifest.json",
        "assets/config.json",
    }
    assert search["results"][0]["relative_path"] == "assets/config.json"


def test_aot_analysis_is_normalized_queryable_and_reused(tmp_path):
    path = make_flutter_xapk(tmp_path)
    analyzer = FakeAnalyzer()
    cache = FlutterAnalysisCache(tmp_path / "cache")
    backend = FlutterBackend(analyzer_factory=lambda options: analyzer, cache=cache)

    first = run(
        backend.open(
            SessionRequest(lifecycle=LifecycleAction.OPEN, target_path=str(path))
        )
    )
    analysis = run(first.invoke("flutter.aot.analyze", {}))
    functions = run(first.invoke("functions.list", {}))
    function = run(first.invoke("functions.get", {"address": "0x1000"}))
    objects = run(first.invoke("flutter.objects.search", {"query": "Voltage"}))
    libraries = run(first.invoke("flutter.libraries.list", {}))
    run(first.close())

    second = run(
        backend.open(
            SessionRequest(lifecycle=LifecycleAction.OPEN, target_path=str(path))
        )
    )
    cached = run(second.invoke("flutter.aot.analyze", {}))
    run(second.close())

    assert analysis["cache_hit"] is False
    assert functions["functions"][0]["name"] == "_App::main"
    assert "ret" in function["assembly"]
    assert objects["results"][0]["path"] == "objs.txt"
    assert libraries["libraries"] == ["package:app/main.dart"]
    assert cached["cache_hit"] is True
    assert analyzer.calls == 1
    assert Path(cached["output_directory"]).is_dir()


def test_flutter_backend_rejects_non_flutter_artifact(tmp_path):
    path = tmp_path / "plain.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"dex")

    with pytest.raises(ReversingMcpError) as raised:
        run(
            FlutterBackend().open(
                SessionRequest(lifecycle=LifecycleAction.OPEN, target_path=str(path))
            )
        )

    assert raised.value.code == "framework_not_detected"


def test_blutter_adapter_rejects_32_bit_flutter_before_execution(tmp_path):
    path = make_flutter_xapk(tmp_path, abi="armeabi-v7a")
    backend = FlutterBackend(
        analyzer_factory=lambda options: BlutterAnalyzer(["missing-blutter"]),
        cache=FlutterAnalysisCache(tmp_path / "cache"),
    )
    session = run(
        backend.open(
            SessionRequest(lifecycle=LifecycleAction.OPEN, target_path=str(path))
        )
    )
    try:
        with pytest.raises(ReversingMcpError) as raised:
            run(session.invoke("flutter.aot.analyze", {}))
    finally:
        run(session.close())

    assert raised.value.code == "unsupported_flutter_abi"
    assert not (tmp_path / "cache").exists()


def test_upstream_blutter_script_requires_toolchain_build_opt_in(tmp_path):
    analyzer = BlutterAnalyzer(["python", "blutter.py"])

    with pytest.raises(ReversingMcpError) as raised:
        analyzer.analyze(
            libapp_path=str(tmp_path / "libapp.so"),
            libflutter_path=str(tmp_path / "libflutter.so"),
            abi="arm64-v8a",
            output_directory=str(tmp_path / "output"),
            timeout=10,
        )

    assert raised.value.code == "implicit_toolchain_build_disabled"


def test_android_artifact_accepts_aab_flutter_layout(tmp_path):
    path = tmp_path / "sample.aab"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("base/assets/flutter_assets/AssetManifest.json", b"{}")
        archive.writestr("base/lib/arm64-v8a/libapp.so", b"\x7fELF")
        archive.writestr("base/lib/arm64-v8a/libflutter.so", b"\x7fELF")
        archive.writestr("base/lib/arm64-v8a/libapp.so-2.part.so", b"\x7fELF")

    artifact = AndroidArtifact(str(path))
    try:
        result = FlutterArtifactInspector(artifact).inspect()
    finally:
        artifact.close()

    assert result["detected"] is True
    assert result["abis"] == ["arm64-v8a"]
    assert result["deferred_loading_units"] == 1
