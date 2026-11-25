# tests/test_analyzer.py
import pytest

from analyzer import rva_to_file_offset

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


# RVA is entry point which is 0x19C0 and the rva and file offset are the same so they end up in the same place on disk and in memory
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
