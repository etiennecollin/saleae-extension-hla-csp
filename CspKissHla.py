"""Saleae Logic 2 HLA: libcsp KISS framing with selectable CSP 1.x/2.x headers."""

from saleae.analyzers import AnalyzerFrame, ChoicesSetting, HighLevelAnalyzer

# KISS framing bytes (libcsp/src/interfaces/csp_if_kiss.c)
FEND = 0xC0
FESC = 0xDB
TFEND = 0xDC
TFESC = 0xDD
KISS_TNC_DATA = 0x00

# Reflected CRC-32C / Castagnoli polynomial.
CRC32C_REFLECTED_POLY = 0x82F63B78

PRIORITY_NAMES = {
    0: "critical",
    1: "high",
    2: "normal",
    3: "low",
}

# CSP v1 flags (libcsp/include/csp/csp_types.h)
CSP_FRES1 = 0x80
CSP_FRES2 = 0x40
CSP_FRES3 = 0x20
CSP_FFRAG = 0x10
CSP_FHMAC = 0x08

# Bit 2 (0x04) is reserved in CSP v1.
CSP_FRDP = 0x02
CSP_FCRC32 = 0x01


def crc32c(data: bytes) -> int:
    """Return libcsp CRC32C: init=0xffffffff, reflected poly, xorout=0xffffffff."""
    crc = 0xFFFFFFFF

    for octet in data:
        crc ^= octet
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ CRC32C_REFLECTED_POLY
            else:
                crc >>= 1

    return crc ^ 0xFFFFFFFF


def _hex(data: bytes) -> str:
    return " ".join("%02X" % b for b in data)


def _ascii(data: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in data)


def _flag_names(flags: int) -> str:
    names = []

    if flags & CSP_FFRAG:
        names.append("FRAG")
    if flags & CSP_FHMAC:
        names.append("HMAC")
    if flags & CSP_FRDP:
        names.append("RDP")
    if flags & CSP_FCRC32:
        names.append("CRC32")

    reserved = flags & ~(CSP_FFRAG | CSP_FHMAC | CSP_FRDP | CSP_FCRC32)

    if reserved:
        names.append("RESERVED=0x%02X" % reserved)

    return ",".join(names) if names else "none"


class CspKissHla(HighLevelAnalyzer):
    """Decode libcsp KISS frames carrying CSP 1.x or CSP 2.x headers."""

    # ---------------------------------------------------------
    # HLA SETTINGS
    # ---------------------------------------------------------

    # Saleae exposes this as a dropdown in the HLA settings.
    # The first choice is the default.
    header_version = ChoicesSetting(
        choices=["1.x", "2.x"],
        label="CSP Header Version",
    )

    # ---------------------------------------------------------
    # OUTPUT FORMATS
    # ---------------------------------------------------------

    result_types = {
        "csp_packet": {
            "format": (
                "CSP {{data.header_version}}"
                " | "
                "{{data.src}} -> {{data.dst}}"
                " | "
                "port {{data.sport}} -> {{data.dport}}"
                " | "
                "{{data.payload_length}} Bytes"
                " | "
                "CRC {{data.crc_status}}"
            )
        },
        "kiss_control": {"format": ("KISS command 0x{{data.command_hex}}: " "{{data.description}}")},
        "kiss_error": {"format": ("KISS/CSP decode error: {{data.reason}}")},
        "uart_error": {"format": ("UART decode error: {{data.error}}")},
    }

    # A corrupted stream without FEND must not grow indefinitely.
    MAX_PACKET_BYTES = 8192

    # ---------------------------------------------------------
    # INITIALIZATION
    # ---------------------------------------------------------

    def __init__(self):
        # Logic 2 supplies the selected ChoicesSetting value
        # as an instance attribute.
        #
        # The fallback preserves the original 1.x behavior
        # in simple test harnesses.
        selected = getattr(self, "header_version", "1.x")
        self._header_version = selected if selected in ("1.x", "2.x") else "1.x"
        self._reset_parser()

    # ---------------------------------------------------------
    # KISS PARSER STATE
    # ---------------------------------------------------------

    def _reset_parser(self):
        self.in_frame = False
        self.expect_command = False
        self.command = None
        self.packet = bytearray()
        self.escape_pending = False
        self.escape_error = False
        self.escape_error_text = ""
        self.packet_start_time = None

    def _start_frame(self, start_time):
        self.in_frame = True
        self.expect_command = True
        self.command = None
        self.packet = bytearray()
        self.escape_pending = False
        self.escape_error = False
        self.escape_error_text = ""
        self.packet_start_time = start_time

    # ---------------------------------------------------------
    # ERROR FRAME
    # ---------------------------------------------------------

    def _error_frame(self, start_time, end_time, reason, raw=b""):
        return AnalyzerFrame(
            "kiss_error",
            start_time,
            end_time,
            {
                "reason": reason,
                "raw_hex": _hex(bytes(raw)),
            },
        )

    # ---------------------------------------------------------
    # CSP HEADER DECODING
    # ---------------------------------------------------------

    def _decode_header(self, header):
        """
        Decode the selected CSP header format.

        CSP 1.x:
            32-bit identifier

            31..30 : Priority
            29..25 : Source
            24..20 : Destination
            19..14 : Destination port
            13..8  : Source port
            7..0   : Flags

        CSP 2.x:
            48-bit identifier

            47..46 : Priority
            45..32 : Destination
            31..18 : Source
            17..12 : Destination port
            11..6  : Source port
            5..0   : Flags

        Both identifiers are big-endian.
        """

        ident = int.from_bytes(header, byteorder="big")

        if self._header_version == "1.x":
            priority = (ident >> 30) & 0x03
            src = (ident >> 25) & 0x1F
            dst = (ident >> 20) & 0x1F
            dport = (ident >> 14) & 0x3F
            sport = (ident >> 8) & 0x3F
            flags = ident & 0xFF
        else:
            priority = (ident >> 46) & 0x03
            dst = (ident >> 32) & 0x3FFF
            src = (ident >> 18) & 0x3FFF
            dport = (ident >> 12) & 0x3F
            sport = (ident >> 6) & 0x3F
            flags = ident & 0x3F

        return {
            "priority": priority,
            "priority_name": PRIORITY_NAMES[priority],
            "src": src,
            "dst": dst,
            "dport": dport,
            "sport": sport,
            "flags": flags,
            "flags_hex": "0x%02X" % flags,
            "flag_names": _flag_names(flags),
        }

    # ---------------------------------------------------------
    # KISS / CSP PACKET DECODING
    # ---------------------------------------------------------

    def _decode_packet(self, start_time, end_time):
        """
        Decode a de-escaped KISS body.

        The KISS command byte has already been removed.
        """

        raw = bytes(self.packet)

        # -----------------------------------------------------
        # KISS COMMAND
        # -----------------------------------------------------

        if self.command != KISS_TNC_DATA:
            return AnalyzerFrame(
                "kiss_control",
                start_time,
                end_time,
                {
                    "command": self.command,
                    "command_hex": "%02X" % self.command,
                    "description": ("not a libcsp TNC_DATA frame; " "CSP decode skipped"),
                    "raw_hex": _hex(raw),
                },
            )

        # -----------------------------------------------------
        # HEADER LENGTH
        # -----------------------------------------------------

        if self._header_version == "1.x":
            header_length = 4
        else:
            header_length = 6

        # Four bytes reserved for the KISS CRC trailer.
        minimum_length = header_length + 4

        if len(raw) < minimum_length:
            return self._error_frame(
                start_time,
                end_time,
                "short CSP %s/KISS frame: %d bytes; "
                "need at least %d"
                % (
                    self._header_version,
                    len(raw),
                    minimum_length,
                ),
                raw,
            )

        # -----------------------------------------------------
        # EXTRACT HEADER / PAYLOAD / CRC
        # -----------------------------------------------------

        header = raw[:header_length]
        payload = raw[header_length:-4]
        crc_rx = int.from_bytes(raw[-4:], byteorder="big")

        # -----------------------------------------------------
        # CRC VALIDATION
        # -----------------------------------------------------

        # libcsp 2.1 calculates CRC over header + payload.
        #
        # Its verifier also accepts the older payload-only
        # CRC for backwards compatibility.
        crc_header_payload = crc32c(raw[:-4])
        crc_payload_only = crc32c(payload)

        if crc_rx == crc_header_payload:
            crc_status = "PASS (header+payload)"
        elif crc_rx == crc_payload_only:
            crc_status = "PASS (legacy payload-only)"
        else:
            crc_status = "FAIL"

        # -----------------------------------------------------
        # DECODE CSP HEADER
        # -----------------------------------------------------

        header_fields = self._decode_header(header)

        # -----------------------------------------------------
        # CREATE CSP PACKET FRAME
        # -----------------------------------------------------

        return AnalyzerFrame(
            "csp_packet",
            start_time,
            end_time,
            {
                "header_version": self._header_version,
                "header_length": header_length,
                "header_hex": _hex(header),
                "priority": header_fields["priority"],
                "priority_name": (header_fields["priority_name"]),
                "src": header_fields["src"],
                "dst": header_fields["dst"],
                "dport": header_fields["dport"],
                "sport": header_fields["sport"],
                "flags": header_fields["flags"],
                "flags_hex": header_fields["flags_hex"],
                "flag_names": header_fields["flag_names"],
                "payload_length": len(payload),
                "payload_hex": _hex(payload),
                "payload_ascii": _ascii(payload),
                "raw_hex": _hex(raw),
                "crc_received": "0x%08X" % crc_rx,
                "crc_calculated_header_payload": ("0x%08X" % crc_header_payload),
                "crc_calculated_payload_only": ("0x%08X" % crc_payload_only),
                "crc_status": crc_status,
                "kiss_escape_error": self.escape_error,
                "kiss_escape_error_text": (self.escape_error_text),
            },
        )

    # ---------------------------------------------------------
    # MAIN DECODER
    # ---------------------------------------------------------

    def decode(self, frame: AnalyzerFrame):
        """
        Called for each frame received from the Async Serial
        analyzer.

        The Async Serial analyzer emits one serial word per
        'data' frame.
        """

        if frame.type != "data":
            return

        # -----------------------------------------------------
        # UART ERROR
        # -----------------------------------------------------

        uart_error = frame.data.get("error")
        if uart_error:
            self._reset_parser()
            return AnalyzerFrame(
                "uart_error",
                frame.start_time,
                frame.end_time,
                {
                    "error": str(uart_error),
                },
            )

        # -----------------------------------------------------
        # GET UART BYTE
        # -----------------------------------------------------

        word = frame.data.get("data", b"")

        if isinstance(word, int):
            word = bytes((word & 0xFF,))
        elif not isinstance(word, (bytes, bytearray)):
            try:
                word = bytes(word)
            except Exception:
                return

        output = []

        # -----------------------------------------------------
        # PROCESS UART BYTES
        # -----------------------------------------------------

        for value in word:
            value = int(value)

            # -------------------------------------------------
            # WAIT FOR KISS FEND
            # -------------------------------------------------

            if not self.in_frame:
                if value == FEND:
                    self._start_frame(frame.start_time)
                continue

            # -------------------------------------------------
            # KISS ESCAPE PROCESSING
            # -------------------------------------------------

            if self.escape_pending:
                self.escape_pending = False
                if value == TFEND:
                    decoded = FEND
                elif value == TFESC:
                    decoded = FESC
                else:
                    # Invalid escape sequence.
                    # libcsp ignores the invalid escape pair.
                    self.escape_error = True
                    self.escape_error_text = "invalid escape DB %02X" % value
                    continue
            elif value == FESC:
                self.escape_pending = True
                continue
            elif value == FEND:
                # A FEND closes a packet only after at least
                # one CSP byte has arrived.
                #
                # libcsp leaves its RX state active on an
                # empty frame. This also handles consecutive
                # FENDs and captures beginning on a delimiter.
                if self.command is not None and len(self.packet) > 0:
                    decoded_frame = self._decode_packet(self.packet_start_time, frame.end_time)
                    if decoded_frame is not None:
                        output.append(decoded_frame)
                    self._reset_parser()

                continue
            else:
                decoded = value

            # -------------------------------------------------
            # KISS COMMAND BYTE
            # -------------------------------------------------

            # The first byte after FEND is the KISS command.
            # libcsp uses TNC_DATA = 0x00.

            if self.expect_command:
                self.command = decoded
                self.expect_command = False
                continue

            # -------------------------------------------------
            # APPEND CSP BYTE
            # -------------------------------------------------

            self.packet.append(decoded)

            # -------------------------------------------------
            # PROTECT AGAINST OVERSIZED FRAMES
            # -------------------------------------------------

            if len(self.packet) > self.MAX_PACKET_BYTES:
                output.append(
                    self._error_frame(
                        self.packet_start_time,
                        frame.end_time,
                        "KISS frame exceeded %d bytes; " "parser reset" % self.MAX_PACKET_BYTES,
                        self.packet,
                    )
                )

                self._reset_parser()

        # -----------------------------------------------------
        # RETURN DECODED FRAMES
        # -----------------------------------------------------

        if not output:
            return None

        if len(output) == 1:
            return output[0]

        return output
