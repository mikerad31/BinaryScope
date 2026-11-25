# tests/test_analyzer.py
from io import BytesIO
from pathlib import Path

import pytest

from analyzer import (
    analyze_file,
    parse_headers,
    read_c_string,
    read_uint,
    rva_to_file_offset,
)

HELLO_EXE = Path(__file__).parent / "samples" / "hello.exe"


# notepad.exe

_SECTION_ROWS = [
    (".text", 0x1000, 0x1000, 0x27000),
    (".rdata", 0x29000, 0x29000, 0xB000),
    (".data", 0x34000, 0x34000, 0x1000),
    (".pdata", 0x37000, 0x35000, 0x2000),
    (".didat", 0x39000, 0x37000, 0x1000),
    (".rsrc", 0x3A000, 0x38000, 0x1F000),
]

SECTIONS = [
    {
        "name": n,
        "virtual_address": va,
        "pointer_to_raw_data": raw,
        "size_of_raw_data": size,
    }
    for n, va, raw, size in _SECTION_ROWS
]
SIZE_OF_HEADERS = 4096


# Entry point 0x19C0 is in .text. Its VA and file offset are both 0x1000,
# so the file offset comes out equal to the RVA
def test_rva_in_text():
    assert rva_to_file_offset(0x19C0, SECTIONS, SIZE_OF_HEADERS) == 0x19C0


def test_rva_in_pdata():
    assert rva_to_file_offset(0x37000, SECTIONS, SIZE_OF_HEADERS) == 0x35000


# RVA is halfway into rsrc section, displacement is 0xF800. 0x38000 + 0xF800 is 0x47800
def test_rva_in_rsrc():
    assert rva_to_file_offset(0x49800, SECTIONS, SIZE_OF_HEADERS) == 0x47800


def test_rva_in_headers():
    assert rva_to_file_offset(0x500, SECTIONS, SIZE_OF_HEADERS) == 0x500


def test_rva_in_data_memory_only_raises():
    with pytest.raises(ValueError):
        rva_to_file_offset(0x36000, SECTIONS, SIZE_OF_HEADERS)


def test_read_uint_2_bytes():
    buffer = BytesIO(b"\x4c\x01")
    assert read_uint(buffer, 2) == 0x14C
    assert buffer.tell() == 2


def test_read_uint_not_enough_bytes():
    buffer = BytesIO(b"\x4c\x01")
    with pytest.raises(ValueError):
        read_uint(buffer, 4)


def test_read_uint_4_bytes():
    buffer = BytesIO(b"\x4c\x01\x8a\xf0")
    assert read_uint(buffer, 4) == 0xF08A014C


def test_read_uint_8_bytes():
    buffer = BytesIO(b"\x00\x00\x00\x40\x01\x00\x00\x00")
    assert read_uint(buffer, 8) == 0x140000000


def test_read_c_string():
    buffer = BytesIO(b"abcKERNEL32.DLL\x00")
    assert read_c_string(buffer, 3, 16) == "KERNEL32.DLL"


def test_read_c_string_no_null():
    buffer = BytesIO(b"abcdefg")
    with pytest.raises(ValueError, match="file-backed"):
        read_c_string(buffer, 0, 7)


def test_read_c_string_4096():
    characters = b"A" * 4096 + b"\x00"
    buffer = BytesIO(characters)
    assert read_c_string(buffer, 0, len(characters)) == "A" * 4096


def test_read_c_string_4097():
    characters = b"A" * 4097 + b"\x00"
    buffer = BytesIO(characters)
    with pytest.raises(ValueError, match="maximum length"):
        read_c_string(buffer, 0, len(characters))


def test_parse_headers_missing_mz():
    buffer = BytesIO(b"\x00")
    with pytest.raises(ValueError, match="Missing MZ"):
        parse_headers(buffer)


def test_parse_headers_missing_pe():
    buffer = BytesIO(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"\x00\x00\x00\x00")
    with pytest.raises(ValueError, match="Missing PE"):
        parse_headers(buffer)


# e_lfanew points past the end of the file, so the PE check still raises
def test_parse_headers_pe_offset_past_end():
    buffer = BytesIO(b"MZ" + b"\x00" * 58 + b"\x00\x10\x00\x00")
    with pytest.raises(ValueError, match="Missing PE"):
        parse_headers(buffer)


def test_parse_headers_invalid_magic_number():
    buffer = BytesIO(
        b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\0\0" + b"\x00" * 40
    )
    with pytest.raises(ValueError, match="Invalid magic number"):
        parse_headers(buffer)


def test_parse_headers_truncated_after_pe_signature():
    buffer = BytesIO(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\0\0")
    with pytest.raises(ValueError, match="Unexpected end"):
        parse_headers(buffer)


def test_parse_headers_optional_header_too_small():
    buffer = BytesIO(
        b"MZ"
        + b"\x00" * 58
        + b"\x40\x00\x00\x00"
        + b"PE\0\0"
        + b"\x00" * 20
        + b"\x0b\x02"
        + b"\x00" * 30
    )
    with pytest.raises(ValueError, match="too small for directory count"):
        parse_headers(buffer)


@pytest.fixture(scope="module")
def hello_analysis():
    return analyze_file(HELLO_EXE)


def test_hello_exe_headers(hello_analysis):
    headers = hello_analysis["headers"]
    assert headers["machine"] == 0x8664
    assert headers["pe_type"] == "PE32+"
    assert headers["image_base"] == 0x140000000


def test_hello_exe_sections(hello_analysis):
    section_names = [section["name"] for section in hello_analysis["sections"]]
    assert section_names == [
        ".text",
        ".data",
        ".rdata",
        ".pdata",
        ".xdata",
        ".bss",
        ".idata",
        ".CRT",
        ".tls",
        ".reloc",
    ]


def test_hello_exe_imports(hello_analysis):
    imports = []
    for entry in hello_analysis["imports"]:
        imports.append(entry["dll"])
    assert imports == ["KERNEL32.dll", "msvcrt.dll"]


def test_hello_exe_truncated(tmp_path):
    data = HELLO_EXE.read_bytes()
    truncated = tmp_path / "truncated.exe"
    truncated.write_bytes(data[:0x400])
    with pytest.raises(ValueError, match="raw data outside file"):
        analyze_file(truncated)


def test_hello_exe_truncated_inside_headers(tmp_path):
    data = HELLO_EXE.read_bytes()
    truncated = tmp_path / "truncated.exe"
    truncated.write_bytes(data[:0x3FF])
    with pytest.raises(ValueError, match="exceeds file size"):
        analyze_file(truncated)
