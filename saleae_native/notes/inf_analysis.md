# Saleae.inf analysis

Source: `C:\Program Files\Logic\Drivers\Saleae.inf`
Driver version: 6.0.6000.16390 (2020-04-01)
Class: `USB` ; Provider: "Saleae Inc"

## VID / PID table

The driver enumerates eight separate USB IDs. All install bind to the generic Microsoft `WinUSB.sys` (see `WinUSB_ServiceInstall`) — there is no proprietary kernel driver. WinUSB means the device is reachable from user-space via the standard `WinUsb_*` API (which the host code in `graph_server_shared.dll` confirms — see `notes/dll_protocol_strings.md`).

| Product                  | VID    | PID    | Device-Interface GUID                              |
|--------------------------|--------|--------|---------------------------------------------------|
| Saleae Logic (orig)      | 0x0925 | 0x3881 | {21459242-8155-11DD-BC59-51D755D89593}            |
| Saleae Logic16           | 0x21A9 | 0x1001 | {D509886E-3AA5-11DF-861E-86B356D89593}            |
| Saleae Logic Start       | 0x21A9 | 0x1002 | {F8BF574A-E31C-40B6-8332-AD51EF1D325D}            |
| Saleae Logic 4           | 0x21A9 | 0x1003 | {DE7E53F9-378A-4DC9-9AE8-2D7619404112}            |
| Saleae Logic 8           | 0x21A9 | 0x1004 | {03C61D2D-8A38-4FD3-9E60-1BCAA5FA28C1}            |
| Saleae Logic Pro 8       | 0x21A9 | 0x1005 | {DDB1D63F-0ECF-4E86-94E7-ADB4C765E352}            |
| Saleae Logic Pro 16      | 0x21A9 | 0x1006 | {DDB1D63F-0ECF-4E86-94E7-ADB4C765E353}            |
| Saleae Logic MSO         | 0x21A9 | 0x1007 | {BE69C8B4-A1D1-4704-8082-7E557F6ECB02}            |

Note: VID `0x0925` is the **legacy "Lakeview Research"** ID that Cypress sold to early customers — used by the original Saleae Logic (FX2-based). The newer Saleae VID is `0x21A9` ("Saleae LLC").

Two PIDs share the GUID prefix `DDB1D63F-0ECF-4E86-94E7-ADB4C765E35X`: Logic Pro 8 (`...352`) and Logic Pro 16 (`...353`). They likely share the same FX3 firmware image with a board-revision flag.

## USB class / driver shape

- `Include=winusb.inf` + `Needs=WINUSB.NT` → WinUSB driver framework.
- `KmdfService=WINUSB, WinUsb_Install` ; `KmdfLibraryVersion=1.7`.
- No interface alt-setting hints, no endpoint addresses, no `bInterfaceClass` in the INF — those have to come from the USB descriptors that the device itself reports. See `notes/live_device.md` for the live descriptors and the (critical) finding that the device boots up with a vendor-class Cypress FX3 boot ROM and reconfigures itself after the host loads firmware / FPGA bitstream.

## Implications for the bridge

- Cross-platform USB lib (`libusb1` or `pyusb` w/ `libusb1` backend on Linux/Mac, `libusb-win32` won't work — must use `WinUSB` on Windows).
- On Windows, opening the device path requires going through `SetupDi*` to find the device-interface GUID then `CreateFileW` on the resulting symbolic link, then `WinUsb_Initialize`. The pyusb `libusb1` backend handles this internally — confirmed in `live_device.md` that pyusb + libusb1 backend can enumerate and read string descriptors fine.
- We can filter `dev.idVendor == 0x21A9` and accept any `0x1001..0x1007`, plus the legacy `(0x0925, 0x3881)` for original Saleae Logic.
