"""Standalone smoke test for the in-IDA notebook viewer's markdown
renderer. Stubs all ida_* modules so we can exercise _md_to_html etc.
without IDA. Run from repo root: `python tests/_render_smoke.py`.

Not part of the pytest suite — the markdown renderer is just enough
plumbing that a one-shot smoke is fine, and pulling the plugin into
pytest pretends-tests is more trouble than it's worth.
"""

import sys
import types
from pathlib import Path

# Stub every IDA module plugin.py touches at import time.
_IDA_STUB_MODULES = [
    "ida_auto", "ida_bytes", "ida_dbg", "ida_funcs", "ida_hexrays",
    "ida_ida", "ida_idaapi", "ida_idd", "ida_kernwin", "ida_netnode",
    "ida_lines", "ida_name", "ida_nalt", "ida_segment", "ida_typeinf",
    "ida_xref", "idautils", "idc",
]
for name in _IDA_STUB_MODULES:
    sys.modules.setdefault(name, types.ModuleType(name))

# PluginForm + action_handler_t need to be subclassable.
sys.modules["ida_kernwin"].PluginForm = type("PluginForm", (object,), {})
sys.modules["ida_kernwin"].action_handler_t = type("action_handler_t", (object,), {})
sys.modules["ida_kernwin"].AST_ENABLE_ALWAYS = 1
sys.modules["ida_kernwin"].msg = lambda *a, **k: None
sys.modules["ida_idaapi"].plugin_t = type("plugin_t", (object,), {})
sys.modules["ida_idaapi"].PLUGIN_KEEP = 0
sys.modules["ida_idaapi"].BADADDR = -1

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ida"))
import plugin  # noqa: E402

SAMPLE = """\
## [2026-05-16 14:32:08 UTC] Discovery

Found `Fx3DeviceFeatures` vtable at **0x1823F22A8**. Class hierarchy:

- `Logic2FpgaDevice` → calls into `Fx3DeviceFeatures`
- `Fx3DeviceFeatures` → wraps `WindowsUsbDevice`

The serializer is at `sub_1807CFBB0` (iLok-virtualized — static dead end).
Live capture instead at 0x1814C4BBB inside `WindowsUsbDevice::Write`.

Captured wire bytes:

| # | Size | Payload |
|---|------|---------|
| 1 | 2    | 54 2A   |
| 2 | 6    | 55 CD 69 19 D2 48 |
| 3 | 2    | 94 D9   |

```c
void __fastcall Fx3DeviceFeatures::WriteEeprom(__int64 self, char *buf) {
  WinUsb_WritePipe(self->handle, 1, buf, 6, 0, 0);
}
```

See also: [datasheet](https://example.com/fx3.pdf).
"""


def main():
    html = plugin._md_to_html(SAMPLE)
    assert "<h2>" in html, "missing h2"
    assert "<strong>" in html or "<b>" in html, "missing bold"
    assert "Fx3DeviceFeatures" in html
    # autolink
    assert 'href="ida://0x1823F22A8"' in html, "0x address not autolinked"
    assert 'href="ida://0x1807CFBB0"' in html, "sub_ pattern not autolinked"
    # link in <a> stays intact, isn't double-linked
    assert html.count('href="https://example.com/fx3.pdf"') == 1
    # external https link must NOT have address inside re-autolinked
    assert "fx3.pdf" in html
    # code-fence content survives
    assert "WinUsb_WritePipe" in html
    # tables are the whole point of this test: must render as <table>
    assert "<table>" in html and "<th>" in html and "<td>" in html, \
        "table not rendered — markdown 'extra' / 'tables' extension missing"
    # the install-fallback page should NOT have fired
    assert "Markdown renderer not available" not in html
    print("OK — render produced", len(html), "chars (table rendered)")


if __name__ == "__main__":
    main()
