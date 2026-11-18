# libcsp KISS / CSP 1.x and 2.x HLA for Saleae Logic 2

This High-Level Analyzer consumes the built-in **Async Serial** analyzer and decodes libcsp KISS transport packets. Select the CSP network-header format in the HLA settings.

## Install

1. In Logic 2, open the Extensions panel.
2. Choose **Load Existing Extension** (or the equivalent local-extension action in your Logic 2 version).
3. Select this extension directory, which contains `extension.json` and `CspKissHla.py`.
4. Add the **Async Serial** analyzer to the UART channel and configure baud rate, data bits, parity, and stop bits.
5. Add **libcsp KISS / CSP 1.x-2.x** as an HLA and select the Async Serial analyzer as its input.
6. In the HLA settings, choose **CSP Header Version** (`1.x` or `2.x`). The default is `1.x` to preserve compatibility with earlier versions of this extension.

## CSP header selection

The HLA does not try to infer the CSP header version from packet bytes. Set the dropdown to match the `csp_conf.version` used by the sender.

| Field            | CSP 1.x | CSP 2.x |
| ---------------- | ------: | ------: |
| Header length    | 4 bytes | 6 bytes |
| Priority         |  2 bits |  2 bits |
| Source node      |  5 bits | 14 bits |
| Destination node |  5 bits | 14 bits |
| Destination port |  6 bits |  6 bits |
| Source port      |  6 bits |  6 bits |
| Flags            |  8 bits |  6 bits |

The packed CSP 1.x identifier is `PRIO | SRC | DST | DPORT | SPORT | FLAGS`. The CSP 2.x identifier is `PRIO | DST | SRC | DPORT | SPORT | FLAGS`; the destination field precedes the source field in the 48-bit v2 identifier. Both are decoded as big-endian network-order integers.

## KISS and CRC behavior

- KISS delimiters: `FEND=0xC0`.
- KISS escapes: `FESC TFEND` decodes to `0xC0`; `FESC TFESC` decodes to `0xDB`.
- The first byte after FEND is treated as the KISS command byte. libcsp transmits `TNC_DATA=0x00`; other command values are shown as `kiss_control` frames and are not parsed as CSP.
- The final four bytes are treated as the KISS CRC trailer. CRC-32C is checked over header + payload first, then payload-only as the libcsp backwards-compatibility fallback.
- CRC failures are still emitted as `csp_packet` frames, with `crc_status=FAIL`, so bad packets remain visible in the capture.
- libcsp's KISS interface appends/checks its CRC regardless of the CSP header `FCRC32` flag; do not use that flag to decide whether the KISS trailer is present.
