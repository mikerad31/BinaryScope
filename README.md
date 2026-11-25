# BinaryScope

#### Video Demo: https://youtu.be/tjH2z1n7BHg

#### Description:

BinaryScope is a local web app that inspects Windows `.exe` and `.dll` files without running them. You upload a file, it parses the PE (Portable Executable) format directly from the bytes, and it shows the architecture, sections, imported DLLs and functions, printable strings, and a SHA-256 hash. Each analysis is saved to SQLite, so old reports can be reopened from a history page without uploading the file again.

It doesn't judge whether a file is safe or malicious, and it never executes what you upload.

I picked PE files because I've always been into lower level stuff and how software works under the hood, and reverse engineering is something I've wanted to get into. After learning C, Python, memory, file handling, writing my own parser seemed like a good way to use all of it.

## Running it

Requires Python 3.11+ and Flask. From the folder with `app.py`:

    python -m pip install -r requirements.txt
    python -m flask --app app run

Open http://127.0.0.1:5000, choose an `.exe` or `.dll` (64 MiB max), and click **Analyze file**. The database is created automatically in `instance/`.
The parser also runs without the web app:

    python analyzer.py path\to\program.exe

## Running the tests

Install pytest, then run the tests from the project folder:

    python -m pip install pytest
    python -m pytest -q

Use `python -m pytest` rather than plain `pytest` so `analyzer.py` can be imported from the project root.

The tests cover normal and edge cases in `rva_to_file_offset`, `read_uint`, `read_c_string`, and `parse_headers`, including malformed PE headers built byte by byte.

`tests/samples/hello.exe` is a small "Hello, World!" program built from `hello.c` with MinGW-w64:

    x86_64-w64-mingw32-gcc -s -o tests/samples/hello.exe tests/samples/hello.c

The integration tests run `analyze_file` on it and check its headers, section names, and imported DLLs against objdump's output. They also make sure truncated copies raise a clean error instead of crashing.

GitHub Actions runs flake8 and the tests on every push to `main`.

## What the report shows

- **Overview:** PE32 or PE32+, architecture, subsystem, image base, entry point, file size, SHA-256
- **Sections:** file offset and size vs. memory address and size, plus read/write/execute flags
- **Imports:** each imported DLL and the functions listed in its import table
- **Strings:** printable ASCII strings (6+ characters) with their file offsets

For Notepad that is 8 sections, 50 imported DLLs, 315 imported functions, and 948 strings.

## Files

- `analyzer.py`: PE parsing (headers, sections, RVA conversion, imports, strings, hash). Also the command-line entry point.
- `app.py`: Flask routes, upload checks, and report rendering.
- `history.py`: creates the database and saves, lists, and loads analyses.
- `schema.sql`: the `analyses` table.
- `templates/`: `layout.html` (shared layout), `index.html` (upload form), `results.html` (report), `history.html` (saved list).
- `static/style.css`: styling.
- `requirements.txt`: Python dependencies.
- `tests/test_analyzer.py`: pytest tests for the parser.
- `tests/samples/`: `hello.c` and the `hello.exe` built from it, used by the tests.
- `.github/workflows/python-app.yml`: runs flake8 and the tests on GitHub Actions.

## How the parser works

I didn't use a PE library like `pefile`, because the point was learning the format.

`analyze_file()` checks for the `MZ` signature, reads the PE header offset stored at `0x3C`, checks the `PE\0\0` signature, then reads the COFF header and optional header. PE32 and PE32+ lay out some fields differently, and the code handles both.

Most pointers inside a PE file are RVAs (relative virtual addresses). These are offsets from the image base once the program is loaded in memory, not positions in the file on disk. `rva_to_file_offset()` finds the section containing the RVA, takes the distance into that section, then adds it to the section's raw file pointer. It only accepts the RVA if that distance is less than `SizeOfRawData`, because `VirtualSize` (size in memory) and `SizeOfRawData` (bytes stored on disk) differ. A section like `.bss` can have memory but no file data. RVAs inside the headers map directly to the same file offset. An RVA that falls in more than one section raises an error.

The import directory is located through the optional header. The parser converts its RVA to a file offset and reads 20-byte import descriptors (five DWORDs) until one is all zeros. Each descriptor has an RVA for the DLL name and one for the lookup table. Lookup entries are 4 bytes in PE32 and 8 in PE32+. The top bit marks an import by ordinal, where the low 16 bits are the ordinal. Otherwise the entry points to a hint/name structure with a 2-byte hint and a null-terminated function name.

Strings are runs of 6+ printable ASCII bytes, saved with their starting offsets. The SHA-256 is computed over the whole file in chunks. The parser checks that headers and the section table fit inside the file.

`/analyze` checks the extension and size, saves the upload to a temp folder, runs `analyze_file()`, saves the report through `history.py`, deletes the temp file and renders `results.html`. `/analyses/<id>` loads the saved JSON and renders the same template.

## Design choices

**History stored as JSON in one row.** Each report is saved as a JSON blob in a single SQLite row, with filename, size, hash, format, architecture, and timestamp in their own columns for the history page. I didn't want separate tables for every section and imported function. Querying individual sections or imports is not as convenient as using separate tables, and big programs will make big rows, but that's acceptable here since history only lists reports and opens one by ID. Opening a saved report only reads from the database, analyzing a file writes to it. Each analysis gets its own record so uploading the same file twice creates two entries instead of deduping by hash. History page shows the 50 newest entries.

**200 strings on the page.** The analyzer extracts and saves every string. I've chosen to only show the first 200 so it stays readable and within a reasonable amount since some programs can contain thousands of strings. Those mostly come from the start of the file, so later strings can be missed.

**64 MiB upload limit.** Browsers send uploads as multipart form data which adds metadata around the file, so the request is slightly larger than the file. The app allows a little extra room for that, then checks the saved file's real size against 64 MiB. The temp upload is deleted after analysis, and only the report is stored.

## Limits

BinaryScope covers selected parts of the PE format. It doesn't support ELF or Mach-O, doesn't disassemble code, and doesn't judge whether a file is malicious. Strings are ASCII only and include some noise, since it scans the whole raw file for printable bytes.
