# `graph_server_shared.dll` — protocol-relevant strings

Source: `C:\Program Files\Logic\resources\windows-x64\graph_server_shared.dll`
Size: ~63 MB ; `strings -n 6` produced ~106 152 lines (raw dump is in a temp file, not committed).

Sub-headings below show *curated* hits — full per-line context elided where the C++ mangled name was uninformative.

## WinUSB API surface (all confirm host-side USB code is in this DLL)

```
WinUsb_Initialize            WinUsb_Free
WinUsb_QueryInterfaceSettings   WinUsb_QueryPipe
WinUsb_GetDescriptor         WinUsb_ControlTransfer
WinUsb_ReadPipe              WinUsb_WritePipe
WinUsb_AbortPipe             WinUsb_ResetPipe
WinUsb_GetPipePolicy         WinUsb_SetPipePolicy
WinUsb_GetOverlappedResult
```

Plus the device-enumeration plumbing:

```
SetupDiGetClassDevsA/W       SetupDiEnumDeviceInfo
SetupDiEnumDeviceInterfaces  SetupDiGetDeviceInterfaceDetailA
SetupDiGetDeviceRegistryProperty{A,W}
SetupDiGetDeviceInstanceIdA  SetupDiOpenDeviceInfoA
CM_Get_Device_IDA            CM_Get_Device_ID_Size
CreateFileW                  DeviceIoControl
```

These all live behind `WindowsUsbDevice` — see the demangled method signatures:

```
WindowsUsbDevice::SendControlTransfer(const UsbControlSetupPacket&, ...)
WindowsUsbDevice::BulkRead(UsbEndpoint&, uchar*, uint, uint64)
WindowsUsbDevice::BulkWrite(UsbEndpoint&, uchar*, uint, uint64)
WindowsUsbDevice::Read(UsbEndpoint&, ...)
WindowsUsbDevice::Write(UsbEndpoint&, ...)
WindowsUsbDevice::ReseedDevice(UsbEndpoint&)
WindowsUsbDevice::ResetEndpoint(UsbEndpoint&)
WindowsUsbDevice::StartReadStream(...)
```

Source paths embedded in the binary (CI box):

```
\graph-io\devices\usb_device\src\WindowsUsbDevice.cpp
\graph-io\devices\usb_device\src\UsbDevice.cpp
\graph-io\devices\devices_manager\src\devices_manager\windows_usb_manager.cpp
\graph-io\io\usb.cpp
\graph-io\peripheral\fpga.cpp
\graph-io\peripheral\fpga_gpif.cpp
\graph-io\peripheral\fpga_waveform.cpp
```

The repo is private (`github.com/saleae/monorepo` per other strings) so we won't get source — but Ghidra will be useful against the .cpp filename string xrefs as anchors.

## Device class hierarchy (from C++ class names and method strings)

```
UsbDevice (abstract)
└── WindowsUsbDevice   (WinUSB backend on Win32)
GenericDevice           (cross-device base)
└── LogicAnalyzerDevice
    ├── LogicDevice                 (original Logic, FX2)
    ├── Logic16Device               (Logic16, FX2)
    │     LoadBitstream / SetLed / SetLv33 / SetupLed /
    │     SendStartRecordingCommand / StartSampling / Stop /
    │     SetLedData / FakeReadThread
    ├── LogicGraduateDevice         (??? — likely a renamed model)
    ├── LogicStudentDevice          (Logic Start, FX2)
    ├── LogicProfessionalDevice     (Pro 8 + Pro 16 base, FX3)
    │     SendStartCommand / SendStartRecordingCommand /
    │     SendStopCommand / StartSampling / Stop /
    │     SetVoltageLevel / TestEeprom / GetPublicKey
    │   ├── LogicProfessional8Device   (Logic Pro 8)
    │   └── LogicProfessional16Device  (Logic Pro 16)
    └── Logic2FpgaDevice            (newer arch, used by Pro family)
          CommonDeviceInit / IsFpgaResponsive / ParseBoardRevision /
          ResetMainDcm / SetAd9637Enabled / SetAds528xDrive /
          SetAds528xEnabled / SetBankPower / SetCaptureParameters /
          CryptoChipVerify / InitHmcad1100 / SetTestPattenHmcad1100 /
          WriteAd9637Register / FakeReadThread

Device feature classes (cap descriptors):
  Fx2DeviceFeatures              -- FX2-based products
  Fx3DeviceFeatures              -- FX3-based products
  FpgaDeviceFeatures             -- everything with an FPGA
    DownloadBitstream
  ProFpgaDeviceFeatures          -- Logic Pro FPGA-specific quirks
    WriteRegisters
```

And the MSO device (oscilloscope) tree is parallel:

```
MsoDevice / MsoDeviceInterface / MsoSpiFlash / MsoFirmware ...
  Mailbox messages: FirmwareInterruptMessage, InitializeMessage,
  PollForInstrumentsMessage, HeartbeatMessage, PollWallPowerMessage,
  InstrumentErrorEventMessage, AddFakeInstrumentMessage,
  RemoveFakeInstrumentMessage, StateMessage, StartFirmwareUpdateMessage
```

## Device-side FX3 firmware command names

These are the **vendor request handler names** baked into the host-side DLL — they describe the command set the FX3 firmware exposes via `bmRequestType=VENDOR/DEVICE`. Each is almost certainly keyed by a 1-byte `bRequest` value that we'll have to determine by decompilation:

```
Batch_CommandHandler                  GetUsbStats_CommandHandler
DebugDestinationUart_CommandHandler   GetUsbEventLog_CommandHandler
EventEnable_CommandHandler            GetWakeReason_CommandHandler
FanControlSettings_CommandHandler     GpifFlush_CommandHandler
FanControlState_CommandHandler        GpifStartStop_CommandHandler
ForceFirmwareFault_CommandHandler     GpioConfigure_CommandHandler
FpgaConfigBegin_CommandHandler        GpioValue_CommandHandler
FpgaConfigEnd_CommandHandler          HeartbeatDetectionTimer_CommandHandler
FpgaConfigWaitForCompletion_CommandHandler   I2cSwitchReset_CommandHandler
GetAfeHardwareVersion_CommandHandler  I2cTransfer_CommandHandler
GetApplicationContext_CommandHandler  InRequest_CommandHandler
GetFirmwareFault_CommandHandler       LpmEnable_CommandHandler
GetFirmwareVersion_CommandHandler     PdUvdmTransfer_CommandHandler
GetHardwareVersion_CommandHandler     PeekDebugWord_CommandHandler
GetPdState_CommandHandler             PokeDebugWord_CommandHandler
GetPmicShutdownSource_CommandHandler  ResetDebugWords_CommandHandler
GetScState_CommandHandler             ResetDevice_CommandHandler
GetTemperatureState_CommandHandler    ScPdProcessingEnable_CommandHandler
                                      SetApplicationContext_CommandHandler
                                      SetOvertemperatureThresholds_CommandHandler
                                      SpiTransfer_CommandHandler
                                      SystemMonitorState_CommandHandler
VendorRequest_CommandHandler          (dispatcher root)
```

Plus the dispatcher error responses:

```
ILLEGAL_CMD     BAD_CMD_ARG     "Unknown USB setup request: type=%d target=%d direction=%d request=%d ..."
```

## Bitstream / firmware loading (Logic Pro 16 boots in raw FX3 ROM mode)

```
FpgaDeviceFeatures::DownloadBitstream
Logic16Device::LoadBitstream
Saleae::MsoDeviceInterface::ProgramFpgaBitstream
Saleae::MsoFpga::GetFpgaBitstreamVersion
Loading custom firmware image to FX3: {}
Bringup started; total bitstream bytes: %d
Bitstream download took
Bitstream Status: Final Version 10.27
Lattice Semiconductor Corporation Bitstream
device_contains_firmware_image={}
"Logic16 loading {} voltage bitstream"
```

Embedded bitstream CRCs (host knows which precompiled bitstream goes with which board variant):

```
Bitstream CRC: 0x25C9  0x36E3  0x6391  0x72FB  0x74EF
               0x80F3  0xCE24  0xD8EC  0xF147  0xF4ED
```

(These suggest 10 separate FPGA images bundled inside the DLL or `pythonlibs/` — likely for different SKUs and voltage rails. *Do not redistribute the bitstreams themselves.*)

## Sample-rate / channel / voltage hooks (high-level API surface)

```
Saleae::Graph::LogicDevice::SetSampleRate
Saleae::Graph::LogicDevice::SetDigitalVoltageThreshold
Saleae::Graph::LogicDeviceNode::HandleSetSampleRate
Saleae::Graph::LogicDeviceNode::HandleSetDigitalVoltageThreshold
DeviceSettings::GetDigitalOnlyPerforamnceOptions    (sic, typo in their code)
DeviceSettings::SetDigitalOnlyPerformanceOption
SampleRateOption::DigitalSampleRateHz
Logic16SampleRateSettings::Logic16SampleRateSettings(uint, uchar)
```

The voltage strings reveal the supported levels: `1.8 Volts`, `3.3+ Volts`, `1.8V to 3.6V`, `3.6V to 5.0V`, `LC1.2 Volts`, plus runtime-configurable analog thresholds.

## Bulk transfer pipeline (the actual data path)

```
BulkReadStream_Read_Ep{:0x}   BulkReadStream_Request_Ep{}
BulkReadThread: Waiting for memory to be available ...
BulkReadFailed{DeviceManagerStopping,DeviceNotFound,Read,Stall,SystemError,
              UnsupportedDevice,UsbError}
BulkWriteFailed{DeviceManagerStopping,DeviceNotFound,Stall,SystemError,
              UnsupportedDevice,UsbError,Write}
```

The `{:0x}` format string confirms the streamed channel is keyed by **endpoint number** — fits the standard FX3 GPIF model where each instrument streams on a dedicated bulk-IN endpoint.

## Analog front-end chips (for context — these are I2C/SPI peripherals the FX3 talks to over its component buses)

- `HMCAD1100`, `Hmcad1100Settings` — Analog Devices 1-channel 8-bit ADC (used for analog capture)
- `AD9637`, `WriteAd9637Register` — Analog Devices 8-channel 12-bit ADC
- `ADS528x` — TI 16-channel pipelined ADC family
- `adc_12qj1600` — TI ADC12QJ1600 (1.6 GSPS) — MSO scope front-end
- `eeprom_at24c64d`, `spi_flash`, `pmic_tps650864`, `clockgen_5p49v6975`,
  `fancontroller_lm96063`, `ioexpander_tca6416a`, `vga_lmh6518`

These don't affect the wire protocol — they're internal to the FX3 firmware — but the names help orient Ghidra navigation.

## What we still need to find via Ghidra decompile

1. The exact `bRequest` value for `VendorRequest_CommandHandler` (the master dispatcher).
2. The mapping `command_id (uint8/16) → *_CommandHandler` (so we can call `GetFirmwareVersion`, `GpioValue`, etc. ourselves).
3. The bulk endpoint addresses post-firmware-load (probably hardcoded constants).
4. The format of `SetCaptureParameters` payload (digital sample rate, voltage threshold, channel mask, trigger config — all packed into a single command).
5. The header/trailer format of sample-stream packets (e.g. how compression / runs are framed; the strings reference "stats packets" with `SamplesPerPacketMultiple_WithStats` constant).
6. Crypto challenge — `CryptoChipVerify`, `CryptoInterfaceI2c`, `CryptoInterfaceFpga`, `GetPublicKey`. There's an authentication step (probably ATSHA204A or ATECC508A) before the device will start streaming. Do NOT extract any private keys; we're documenting that it exists so we know we may need to skip features that rely on it.
