"""
SaleaeDevice -- skeleton USB driver class.

All methods that touch the wire raise NotImplementedError pending protocol
RE (see saleae_native/notes/). The shape is fixed; only the bodies need
filling in once Ghidra has revealed the per-command byte layout.

Dependency: prefer `libusb1` (cross-platform; works against WinUSB on
Windows without code changes) over `pyusb`. The live-device enumeration
in `notes/live_device.md` was done via `libusb1` and confirmed working.
Listed as a TODO -- the actual import is deferred to `open()` so the
module can be loaded for testing/stub purposes without libusb installed.

Reference for the PID table: `notes/inf_analysis.md`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# (vid, pid) -> human-readable model. From Saleae.inf.
KNOWN_DEVICES: dict[tuple[int, int], str] = {
    (0x0925, 0x3881): "Saleae Logic (orig)",          # FX2-based
    (0x21A9, 0x1001): "Saleae Logic16",                # FX2-based
    (0x21A9, 0x1002): "Saleae Logic Start",            # FX2-based
    (0x21A9, 0x1003): "Saleae Logic 4",                # FX2-based
    (0x21A9, 0x1004): "Saleae Logic 8",                # FX2-based
    (0x21A9, 0x1005): "Saleae Logic Pro 8",            # FX3-based
    (0x21A9, 0x1006): "Saleae Logic Pro 16",           # FX3-based
    (0x21A9, 0x1007): "Saleae Logic MSO",              # FX3-based
}

# Devices that need firmware/bitstream uploaded before they expose bulk EPs.
# Set per-PID after we determine empirically (notes/live_device.md confirms
# Pro 16 starts in raw Cypress FX3 boot ROM mode with numEP=0).
FX3_PIDS = {0x1005, 0x1006, 0x1007}
FX2_PIDS = {0x1001, 0x1002, 0x1003, 0x1004}


@dataclass
class DeviceIdentity:
    vid: int
    pid: int
    serial: str
    model: str
    bus: int
    address: int
    operating_mode: bool   # True iff firmware/bitstream already loaded


class SaleaeDevice:
    """Thin USB wrapper around a single Saleae logic analyzer.

    All transfer methods are placeholders. The shape of the public API is
    designed to mirror what the bridge endpoints in `bridge.py` will need.
    """

    def __init__(self, vid: int, pid: int, serial: Optional[str] = None):
        self.vid = vid
        self.pid = pid
        self.serial = serial
        self.identity: Optional[DeviceIdentity] = None
        self._handle = None        # libusb1 USBDeviceHandle when open
        self._intf_claimed = False
        self._ep_cmd_out: Optional[int] = None  # bulk-OUT for commands
        self._ep_cmd_in: Optional[int] = None   # bulk-IN for responses
        self._ep_data_in: Optional[int] = None  # bulk-IN for sample stream

    # -- lifecycle -------------------------------------------------------

    def open(self) -> DeviceIdentity:
        """Find + open the device, claim the WinUSB interface, populate
        endpoint addresses.

        Will:
        1. enumerate via libusb1 filtering by (vid, pid[, serial]),
        2. detect whether the device is in boot-ROM mode (numEndpoints == 0
           for FX3, or no operating-mode descriptor for FX2),
        3. if boot-mode: upload firmware + (FX3 only) FPGA bitstream, wait
           for re-enumeration, re-open,
        4. claim interface 0 alt 0,
        5. fill in self._ep_cmd_out / _ep_cmd_in / _ep_data_in from the
           operating-mode descriptors.

        Raises NotImplementedError --- protocol RE pending.
        """
        raise NotImplementedError("pending protocol RE")

    def close(self) -> None:
        """Release interface, close USB handle, leave the device idle.

        Does not unload firmware (FX3 keeps it until power-cycle).

        Raises NotImplementedError --- protocol RE pending.
        """
        raise NotImplementedError("pending protocol RE")

    # -- low-level wire helpers -----------------------------------------

    def _send_command(self, opcode: int, payload: bytes = b"") -> bytes:
        """Send a single vendor-style command and read the response.

        This corresponds to one round-trip through
        `VendorRequest_CommandHandler` on the FX3 side, or possibly a
        bulk-out / bulk-in pair --- the wire shape is one of the things
        we still need to confirm in Ghidra.

        Args:
            opcode: 1- or 2-byte command identifier (TBD from
                xref'ing each `*_CommandHandler` symbol back to the
                dispatcher table inside `VendorRequest_CommandHandler`).
            payload: opcode-specific argument bytes.

        Returns:
            The response body (with any framing already stripped).

        Raises NotImplementedError --- protocol RE pending.
        """
        raise NotImplementedError("pending protocol RE")

    def _read_response(self, size: int) -> bytes:
        """Read `size` bytes from the command-response endpoint.

        Used when a command produces a stream of follow-up packets
        (e.g. `GetUsbEventLog`).

        Raises NotImplementedError --- protocol RE pending.
        """
        raise NotImplementedError("pending protocol RE")

    # -- high-level operations (mirror the MCP tool surface) -------------

    def device_info(self) -> dict:
        """Return identity + firmware version + hardware version.

        Will call (TBD opcodes):
            GetFirmwareVersion_CommandHandler
            GetHardwareVersion_CommandHandler
            GetAfeHardwareVersion_CommandHandler
            ParseBoardRevision  (host-side; reads the EEPROM via I2cTransfer)

        Raises NotImplementedError --- protocol RE pending.
        """
        raise NotImplementedError("pending protocol RE")

    def set_sample_rate(self, rate_hz: int) -> None:
        """Configure digital sample rate.

        Maps to `Saleae::Graph::LogicDevice::SetSampleRate` -> several
        FPGA register writes via `WriteRegisters` /
        `SetCaptureParameters`. Encoded layout TBD.
        """
        raise NotImplementedError("pending protocol RE")

    def set_channels(self, channels: list[int]) -> None:
        """Configure channel mask.

        Maps to FPGA channel-enable register writes inside
        `SetCaptureParameters`.
        """
        raise NotImplementedError("pending protocol RE")

    def set_voltage_threshold(self, volts: float) -> None:
        """Configure digital input voltage threshold.

        Pro family: writes a DAC value via SPI; older Logic family:
        toggles `SetLv33` between 1.8V and 3.3V bitstream variants.
        """
        raise NotImplementedError("pending protocol RE")

    def start_capture(self) -> None:
        """Send `SendStartRecordingCommand` -> arm the FPGA / GPIF state
        machine -> begin filling the bulk-IN sample endpoint."""
        raise NotImplementedError("pending protocol RE")

    def stop_capture(self) -> None:
        """Send `SendStopCommand` -> drain remaining samples -> idle."""
        raise NotImplementedError("pending protocol RE")

    def read_samples(self, max_bytes: int) -> bytes:
        """Pull up to `max_bytes` raw sample bytes off the bulk-IN data
        endpoint. The bridge layer is responsible for buffering / RLE
        decoding (the stream format is documented in strings as having
        "stats packets" interleaved -- see `FpgaConstants::
        SamplesPerPacketMultiple_WithStats`)."""
        raise NotImplementedError("pending protocol RE")

    def set_digital_out(self, channel: int, value: int) -> None:
        """Drive a GPIO output pin.

        Maps directly to `GpioConfigure_CommandHandler` +
        `GpioValue_CommandHandler` on the FX3 side. Useful for future
        debug-port-finder workflow (wiggle pins, watch for a response on
        any of the other channels).
        """
        raise NotImplementedError("pending protocol RE")
