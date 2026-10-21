from __future__ import annotations

import asyncio
import io
import zipfile

import pytest

from reversing_mcp.android_artifacts import AndroidArtifact, javascript_modules
from reversing_mcp.errors import ReversingMcpError
from reversing_mcp.providers import local_bridges


APP_SERVICE = b"""
webpackJsonp([0],{
/* 12 */
(function(module, exports) {uni.startBluetoothDevicesDiscovery();}),
/* 13 */
(function(module, exports) {plus.bluetooth.openBluetoothAdapter();})
});
__definePage('pages/index/index', function(){});
"""


def apk_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"binary manifest")
        archive.writestr("classes.dex", b"dex\nio.dcloud.feature")
        archive.writestr("assets/apps/H123/www/app-service.js", APP_SERVICE)
        archive.writestr(
            "assets/apps/H123/www/pages.json",
            b'{"pages":[{"path":"pages/settings/settings"}]}',
        )
    return output.getvalue()


def make_xapk(tmp_path):
    path = tmp_path / "sample.xapk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", b'{"name":"sample"}')
        archive.writestr("base.apk", apk_bytes())
        archive.writestr("config.en.apk", apk_bytes()[:100])
    return path


def run(coroutine):
    return asyncio.run(coroutine)


def test_xapk_nested_search_pretty_dcloud_and_extract(tmp_path):
    artifact = AndroidArtifact(str(make_xapk(tmp_path)))
    try:
        entries = artifact.list_entries({"suffix": "app-service.js"})
        assert entries["entries"][0]["path"] == (
            "base.apk!/assets/apps/H123/www/app-service.js"
        )

        search = artifact.javascript_search(
            {"query": "plus.bluetooth", "context_chars": 40}
        )
        assert search["results"][0]["line"] > 1
        assert "openBluetoothAdapter" in search["results"][0]["context"]

        source = artifact.javascript_source(
            {
                "path": "base.apk!/assets/apps/H123/www/app-service.js",
                "module_id": "13",
            }
        )
        assert source["module_id"] == "13"
        assert "openBluetoothAdapter" in source["source"]
        assert source["formatter"] in {"builtin", "prettier"}

        dcloud = artifact.dcloud_inspect()
        assert dcloud["detected"] is True
        assert dcloud["apps"][0]["app_id"] == "H123"
        assert "pages/index/index" in dcloud["apps"][0]["pages"]
        assert "pages/settings/settings" in dcloud["apps"][0]["pages"]

        result = artifact.extract({"path": "base.apk!/assets/apps/H123/www/pages.json"})
        extracted = result["files"][0]
        assert result["temporary"] is True
        assert extracted["size"] > 0
        assert artifact.primary_apk().read_bytes() == apk_bytes()
    finally:
        temporary = artifact.temporary_directory
        artifact.close()
    assert not temporary.exists()


def test_javascript_module_inventory_handles_webpack_comments():
    modules = javascript_modules(APP_SERVICE.decode())
    assert [module.module_id for module in modules] == ["12", "13"]


def test_source_view_selects_smallest_function_at_location(tmp_path):
    apk = tmp_path / "function.apk"
    source = b"function outer() { function inner() { return 42; } return inner(); }"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/apps/A/www/app-service.js", source)
    artifact = AndroidArtifact(str(apk))
    try:
        result = artifact.javascript_source(
            {
                "path": "assets/apps/A/www/app-service.js",
                "offset": source.index(b"return 42"),
            }
        )
    finally:
        artifact.close()

    assert result["module_id"] == "function:inner"
    assert "return 42" in result["source"]
    assert "return inner" not in result["source"]


def test_extraction_rejects_archive_traversal(tmp_path):
    apk = tmp_path / "unsafe.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("../outside.js", b"alert(1)")
    artifact = AndroidArtifact(str(apk))
    try:
        with pytest.raises(ReversingMcpError) as raised:
            artifact.extract({"path": "../outside.js"})
    finally:
        artifact.close()

    assert raised.value.code == "unsafe_archive_path"
    assert not (tmp_path / "outside.js").exists()


def test_jadx_session_routes_canonical_source_operations(tmp_path):
    artifact = AndroidArtifact(str(make_xapk(tmp_path)))
    session = local_bridges.JadxSession(
        provider_id="jadx",
        registration={"port": 13537, "mode": "headless", "owned": True},
        target_path=str(artifact.path),
        database_path="",
        capabilities=local_bridges.JADX_CAPABILITIES,
        operations=local_bridges.JADX_OPERATIONS,
        endpoint_map=local_bridges._JADX_ENDPOINTS,
        owned=True,
        read_only=True,
        artifact=artifact,
    )
    try:
        result = run(session.invoke("source.search", {"query": "plus.bluetooth"}))
    finally:
        artifact.close()

    assert len(result["results"]) == 1
    assert result["results"][0]["path"].startswith("base.apk!/")
