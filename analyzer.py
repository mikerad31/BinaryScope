import hashlib
import sys
from datetime import UTC, datetime


def read_uint(file, size):
    raw = file.read(size)

    if len(raw) != size:
        raise ValueError("Unexpected end of file")

    return int.from_bytes(raw, byteorder="little")


def file_backed_end(offset, sections, size_of_headers):
    # Don't let import names or tables run past their section
    if 0 <= offset < size_of_headers:
        return size_of_headers

    for section in sections:
        start = section["pointer_to_raw_data"]
        end = start + section["size_of_raw_data"]

        if start <= offset < end:
            return end

    raise ValueError("Offset outside file-backed sections")


def parse_headers(file):
    file.seek(0)
    signature = file.read(2)

    if signature != b"MZ":
        raise ValueError("Missing MZ signature")

    # The DOS header stores the PE header offset at 0x3C
    file.seek(0x3C)
    pe_offset = read_uint(file, 4)
    file.seek(pe_offset)
    pe_signature = file.read(4)

    if pe_signature != b"PE\0\0":
        raise ValueError("Missing PE signature")

    coff_file_header_offset = file.tell()
    machine = read_uint(file, 2)
    number_of_sections = read_uint(file, 2)
    time = datetime.fromtimestamp(read_uint(file, 4), UTC)
    file.seek(coff_file_header_offset + 16)
    size_of_optional_header = read_uint(file, 2)
    characteristics = read_uint(file, 2)
    optional_header_offset = coff_file_header_offset + 20
    file.seek(optional_header_offset)
    magic = read_uint(file, 2)
    file.seek(optional_header_offset + 16)
    entry_point = read_uint(file, 4)

    # PE32 and PE32+ have different optional header layouts
    if magic == 0x10B:
        pe_type = "PE32"
        file.seek(optional_header_offset + 28)
        image_base = read_uint(file, 4)
        rva_count_offset = 92
        import_directory_offset = 104

    elif magic == 0x20B:
        pe_type = "PE32+"
        file.seek(optional_header_offset + 24)
        image_base = read_uint(file, 8)
        rva_count_offset = 108
        import_directory_offset = 120

    else:
        raise ValueError("Unsupported Optional Header magic")

    if size_of_optional_header < rva_count_offset + 4:
        raise ValueError("Optional Header too small for directory count")

    file.seek(optional_header_offset + rva_count_offset)
    number_of_rva_and_sizes = read_uint(file, 4)
    available_directories = (size_of_optional_header - (rva_count_offset + 4)) // 8

    if number_of_rva_and_sizes > available_directories:
        raise ValueError("Data directory count exceeds Optional Header")

    if number_of_rva_and_sizes < 2:
        import_directory_rva = 0
        import_directory_size = 0

    elif size_of_optional_header < import_directory_offset + 8:
        raise ValueError("Optional Header too small to contain import directory")

    else:
        file.seek(optional_header_offset + import_directory_offset)
        import_directory_rva = read_uint(file, 4)
        import_directory_size = read_uint(file, 4)

    file.seek(optional_header_offset + 60)
    size_of_headers = read_uint(file, 4)
    section_table_offset = optional_header_offset + size_of_optional_header
    file.seek(optional_header_offset + 68)
    subsystem = read_uint(file, 2)

    return {
        "pe_offset": pe_offset,
        "machine": machine,
        "number_of_sections": number_of_sections,
        "timestamp": time,
        "size_of_optional_header": size_of_optional_header,
        "characteristics": characteristics,
        "magic": magic,
        "pe_type": pe_type,
        "entry_point": entry_point,
        "image_base": image_base,
        "subsystem": subsystem,
        "section_table_offset": section_table_offset,
        "number_of_rva_and_sizes": number_of_rva_and_sizes,
        "import_directory_rva": import_directory_rva,
        "import_directory_size": import_directory_size,
        "size_of_headers": size_of_headers,
    }


def machine_type(machine):
    machine_types = {
        0x014C: "Intel x86",
        0x8664: "AMD64 / x64",
        0xAA64: "ARM64",
    }
    return machine_types.get(machine, f"Unknown machine ({hex(machine)})")


def subsystem_type(subsystem):
    subsystems = {
        0: "Unknown",
        1: "Device drivers and native Windows processes",
        2: "Windows GUI",
        3: "Windows CUI / console application",
        5: "OS/2 character",
        7: "Posix character",
        8: "Native Win9x driver",
        9: "Windows CE",
        10: "EFI application",
        11: "EFI driver with boot services",
        12: "EFI driver with run-time services",
        13: "EFI ROM image",
        14: "XBOX",
        16: "Windows boot applications",
    }
    return subsystems.get(subsystem, f"Unknown subsystem ({subsystem})")


def parse_sections(file, offset, count):
    sections = []

    file.seek(offset)
    for _ in range(count):
        # Each section header is 40 bytes
        section_header = file.read(40)
        if len(section_header) != 40:
            raise ValueError("Unexpected end of section header")
        name = section_header[0:8].rstrip(b"\x00").decode("ascii", errors="replace")
        virtual_size = int.from_bytes(section_header[8:12], "little")
        virtual_address = int.from_bytes(section_header[12:16], "little")
        size_of_raw_data = int.from_bytes(section_header[16:20], "little")
        pointer_to_raw_data = int.from_bytes(section_header[20:24], "little")
        characteristics = int.from_bytes(section_header[36:40], "little")
        section = {
            "name": name,
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "size_of_raw_data": size_of_raw_data,
            "pointer_to_raw_data": pointer_to_raw_data,
            "characteristics": characteristics,
        }
        sections.append(section)

    return sections


def decode_section_characteristics(characteristics):
    options = {
        0x00000020: "CODE",
        0x00000040: "INITIALIZED_DATA",
        0x00000080: "UNINITIALIZED_DATA",
        0x02000000: "DISCARDABLE",
        0x04000000: "NOT_CACHED",
        0x08000000: "NOT_PAGED",
        0x10000000: "SHARED",
        0x20000000: "EXECUTE",
        0x40000000: "READ",
        0x80000000: "WRITE",
    }
    flags = []

    for flag, desc in options.items():
        if characteristics & flag:
            flags.append(desc)

    return flags


def calculate_sha256(path):
    chunk_size = 1024 * 1024
    sha256 = hashlib.sha256()

    with open(path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def extract_strings(path, min_length=6):
    strings = []
    chunk_size = 1024 * 1024
    file_offset = 0
    start_offset = None
    current = ""

    # Keep the current string if it continues into the next chunk
    with open(path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                if len(current) >= min_length:
                    strings.append({"offset": start_offset, "value": current})
                break
            for byte in chunk:
                if 0x20 <= byte <= 0x7E:
                    if current == "":
                        start_offset = file_offset
                    current += chr(byte)
                else:
                    if len(current) >= min_length:
                        strings.append({"offset": start_offset, "value": current})
                    current = ""
                file_offset += 1

    return strings


def rva_to_file_offset(rva, sections, size_of_headers):
    file_offset = None

    if 0 <= rva < size_of_headers:
        return rva

    for section in sections:
        displacement = rva - section["virtual_address"]

        if 0 <= displacement < section["size_of_raw_data"]:
            if file_offset is not None:
                raise ValueError("RVA maps to multiple sections")

            file_offset = section["pointer_to_raw_data"] + displacement

    # Some RVAs only exist in memory, not in the file
    if file_offset is None:
        raise ValueError("RVA is not backed by section file data")

    return file_offset


def parse_import_descriptors(
    file, import_offset, import_size, sections, size_of_headers
):
    file.seek(import_offset)
    import_contents = []

    remaining = (
        file_backed_end(import_offset, sections, size_of_headers) - import_offset
    )

    if import_size > remaining:
        raise ValueError("Import directory exceeds file-backed region")

    for _ in range(import_size // 20):
        contents = {
            "import_lookup_rva": read_uint(file, 4),
            "timestamp": read_uint(file, 4),
            "forwarder_chain": read_uint(file, 4),
            "name_rva": read_uint(file, 4),
            "import_address_rva": read_uint(file, 4),
        }

        # An empty descriptor marks the end of the import list.
        if not any(contents.values()):
            break

        import_contents.append(contents)

    else:
        raise ValueError("Import directory missing null descriptors")

    return import_contents


def read_c_string(file, offset, end_offset):
    file.seek(offset)
    name = bytearray()

    while True:
        if file.tell() >= end_offset:
            raise ValueError("String exceed file-backed section")

        character = read_uint(file, 1)

        if character == 0:
            break

        if len(name) >= 4096:
            raise ValueError("String exceeds maximum length")

        name.append(character)

    return name.decode("ascii")


def parse_import_lookup_table(
    file, lookup_file_offset, sections, pe_type, size_of_headers
):
    file.seek(lookup_file_offset)
    if pe_type == "PE32":
        entry_size = 4
        flag_mask = 0x80000000
    else:
        entry_size = 8
        flag_mask = 0x8000000000000000
    entries = []

    section_end = file_backed_end(lookup_file_offset, sections, size_of_headers)
    max_entries = (section_end - lookup_file_offset) // entry_size

    for _ in range(max_entries):
        entry = read_uint(file, entry_size)

        if entry == 0:
            break

        entries.append(entry)

    else:
        raise ValueError("Import lookup table missing null terminator")

    functions = []
    for entry in entries:
        # High bit indicates an ordinal import rather than a name RVA
        if entry & flag_mask:
            if entry & ~(flag_mask | 0xFFFF):
                raise ValueError("Invalid ordinal import entry")

            ordinal = entry & 0xFFFF
            functions.append({"ordinal": ordinal})

        else:
            if entry > 0x7FFFFFFF:
                raise ValueError("Invalid import name RVA")

            entry_offset = rva_to_file_offset(entry, sections, size_of_headers)
            entry_end = file_backed_end(entry_offset, sections, size_of_headers)

            if entry_offset + 2 >= entry_end:
                raise ValueError("Incomplete import Hint/Name structure")

            file.seek(entry_offset)
            hint = read_uint(file, 2)
            name = read_c_string(file, file.tell(), entry_end)

            functions.append(
                {
                    "name": name,
                    "hint": hint,
                }
            )

    return functions


def parse_imports(file, headers, sections):
    imports = []

    import_rva = headers["import_directory_rva"]
    import_size = headers["import_directory_size"]

    if not import_rva and not import_size:
        return imports

    if not import_rva or not import_size:
        raise ValueError("Inconsistent import directory RVA and size")

    import_directory_offset = rva_to_file_offset(
        import_rva, sections, headers["size_of_headers"]
    )

    import_contents = parse_import_descriptors(
        file, import_directory_offset, import_size, sections, headers["size_of_headers"]
    )

    for import_content in import_contents:
        if not import_content["name_rva"]:
            raise ValueError("Import descriptor missing DLL name RVA")

        name_file_offset = rva_to_file_offset(
            import_content["name_rva"], sections, headers["size_of_headers"]
        )

        # Use the address table if there's no separate lookup table
        lookup_rva = (
            import_content["import_lookup_rva"] or import_content["import_address_rva"]
        )

        if not lookup_rva:
            raise ValueError("Import descriptor missing lookup table")

        lookup_file_offset = rva_to_file_offset(
            lookup_rva, sections, headers["size_of_headers"]
        )

        functions = parse_import_lookup_table(
            file,
            lookup_file_offset,
            sections,
            headers["pe_type"],
            headers["size_of_headers"],
        )

        dll = read_c_string(
            file,
            name_file_offset,
            file_backed_end(name_file_offset, sections, headers["size_of_headers"]),
        )

        imports.append(
            {
                "dll": dll,
                "functions": functions,
            }
        )

    return imports


def analyze_file(path):
    with open(path, "rb") as file:
        headers = parse_headers(file)

        sections = parse_sections(
            file, headers["section_table_offset"], headers["number_of_sections"]
        )

        file.seek(0, 2)
        file_size = file.tell()

        size_of_headers = headers["size_of_headers"]

        section_table_end = headers["section_table_offset"] + len(sections) * 40

        if section_table_end > size_of_headers:
            raise ValueError("Section table exceeds SizeOfHeaders")

        if size_of_headers > file_size:
            raise ValueError("SizeOfHeaders exceeds file size")

        for section in sections:
            start = section["pointer_to_raw_data"]
            size = section["size_of_raw_data"]
            virtual_size = section["virtual_size"]

            if size:
                if start == 0 or start + size > file_size:
                    raise ValueError("Section raw data outside file")

                if start < size_of_headers:
                    raise ValueError("Section raw data overlaps PE headers")

            if (size or virtual_size) and section["virtual_address"] < size_of_headers:
                raise ValueError("Section RVA overlaps PE headers")

        imports = parse_imports(file, headers, sections)
        strings = extract_strings(path)
        sha256 = calculate_sha256(path)

    return {
        "file_size": file_size,
        "headers": headers,
        "sections": sections,
        "imports": imports,
        "strings": strings,
        "sha256": sha256,
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: analyzer.py example.exe")
        sys.exit(1)

    try:
        results = analyze_file(sys.argv[1])
        headers = results["headers"]

        print(f"Architecture: {machine_type(headers['machine'])}")
        print(f"Format: {headers['pe_type']}")
        print(f"Subsystem: {subsystem_type(headers['subsystem'])}")
        print(f"Image base: {hex(headers['image_base'])}")
        print(f"Entry Point RVA: {hex(headers['entry_point'])}")
        print(f"Size of headers: {hex(headers['size_of_headers'])}")
        print(f"Sections: {headers['number_of_sections']}")

        for section in results["sections"]:
            print(section["name"])
            print(f"    RVA: {hex(section['virtual_address'])}")
            print(f"    Virtual Size: {section['virtual_size']}")
            print(f"    File Offset: {hex(section['pointer_to_raw_data'])}")
            print(f"    Raw Size: {section['size_of_raw_data']}")
            print(
                f"    Flags: "
                f"{decode_section_characteristics(section['characteristics'])}"
            )

        print(f"SHA-256: {results['sha256']}")

        print("Imports:")
        for imported_dll in results["imports"]:
            print(f"    {imported_dll['dll']}")

            for function in imported_dll["functions"]:
                if "name" in function:
                    print(f"        {function['name']}")
                else:
                    print(f"        Ordinal: {function['ordinal']}")

        print(f"Extracted ASCII strings: {len(results['strings'])}")

    except FileNotFoundError:
        print("File not found")
        sys.exit(1)

    except ValueError as error:
        print(f"Invalid PE: {error}")
        sys.exit(1)

    except OSError as error:
        print(f"Unable to read file: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
