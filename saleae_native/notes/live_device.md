# Live device enumeration

Single connected device at time of analysis:

```
FriendlyName : Saleae Logic Pro 16 USB Logic Analyzer
Status       : OK
InstanceId   : USB\VID_21A9&PID_1006\0000000004BE
HardwareID   : USB\VID_21A9&PID_1006&REV_0100 ; USB\VID_21A9&PID_1006
CompatibleID : USB\COMPAT_VID_21A9&Class_FF&SubClass_00&Prot_00, ...
```

Bus class = `0xFF` (vendor-specific) — consistent with WinUSB binding.

## libusb1 descriptor dump

```
=== USB device VID=0x21a9 PID=0x1006 ===
  bcdUSB        = 0x0200
  bcdDevice     = 0x0100
  bDeviceClass  = 0
  bDeviceSubCls = 0
  bDeviceProto  = 0
  bMaxPacketSize0 = 64
  speed         = 3   (High-speed USB 2.0)
  Manufacturer  = 'Cypress'
  Product       = 'WestBridge '
  Serial        = '0000000004BE'
  Configuration #1  attrs=0x80  maxPower=200mA  numIntf=1
    Interface 0 alt=0 class=255 sub=0 proto=0 numEP=0
```

## CRITICAL FINDING — "WestBridge" / no endpoints

The device currently reports **Manufacturer="Cypress", Product="WestBridge ", numEP=0** — this is **not** the operating Saleae descriptor. It's the **Cypress FX3 boot ROM** descriptor (FX3 is the EZ-USB SuperSpeed bridge controller; "West Bridge" is the marketing codename Cypress used for the FX-series).

Why this matters:

- The strings dump of `graph_server_shared.dll` references `FpgaDeviceFeatures::DownloadBitstream`, `Logic16Device::LoadBitstream`, `Loading custom firmware image to FX3: {}`, multiple `Bitstream CRC: 0x...` literals, and the device-side firmware command names `FpgaConfigBegin_CommandHandler`, `FpgaConfigWaitForCompletion_CommandHandler`.
- The flow is: host enumerates the device in **boot mode** (no endpoints, no operating PID), uses **Cypress FX3 boot vendor commands** (well-known: `0xA0` = "load RAM" or specifically the Cypress `CY_BOOT_VID_REQ_*`) to push **two** payloads:
  1. ARM firmware for the FX3 itself (the `_CommandHandler` set we saw in strings)
  2. An FPGA bitstream (Lattice) that the FX3 then clocks into the FPGA over GPIF/SPI
- After both payloads are loaded the FX3 re-enumerates with the proper EP layout (probably EP1-OUT for commands, EP2-IN bulk for sample data, possibly more). We do NOT have those operating descriptors yet — we'd need to run Logic 2 once, capture a Wireshark USBPcap, then re-enumerate to read the post-firmware descriptors.

## Next-step descriptor capture

Two ways:

1. **Wireshark / USBPcap**: launch Saleae Logic 2 once, capture the enumeration + first capture command sequence. The first ~50 packets will contain the firmware upload via `bRequest=0xA2` (Cypress FX3 RAM load) or vendor commands, then the re-enumeration.
2. **Ask the device directly while it's in operating mode**: after Logic 2 has loaded firmware, run `pyusb` enumeration with the same VID/PID — the descriptor will be different. Logic 2 must remain running (or you must replay the firmware load yourself).

## libusb backends

- `python -c "import usb.core"` works (pyusb installed).
- `python -c "import usb1"` works (libusb1 installed).
- pyusb's default backend doesn't find the WinUSB-bound device; **libusb1 raw API does** — that's what produced the dump above. The MCP driver should depend on `libusb1` rather than pyusb.

## Other related Saleae devices to test in the future

- Original Saleae Logic — VID 0x0925 / PID 0x3881 — uses Cypress FX2LP instead of FX3; a completely different firmware-load protocol (FX2 ships an empty 8051 ROM; commands `0xA0 ANCHOR_LOAD_INTERNAL` and renumeration are the standard Cypress dance). Out of scope for first MCP cut.
- Logic16 / Logic 4 / Logic 8 — also FX2-based per the `Logic16Device` C++ class strings; should share the FX2 protocol shape.
- Pro 8 / Pro 16 / MSO — FX3-based per the `Fx3DeviceFeatures` / `Logic2FpgaDevice` / `ProFpgaDeviceFeatures` strings. The connected device is one of these (Pro 16).
