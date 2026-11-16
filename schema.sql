CREATE TABLE
    IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY,
        filename TEXT NOT NULL,
        file_size INTEGER NOT NULL CHECK (file_size >= 0),
        sha256 TEXT NOT NULL CHECK (
            length (sha256) = 64
            AND sha256 NOT GLOB '*[^0-9a-fA-F]*'
        ),
        pe_format TEXT NOT NULL CHECK (pe_format IN ('PE32', 'PE32+')),
        architecture TEXT NOT NULL,
        analyzed_at TEXT NOT NULL,
        report_json TEXT NOT NULL CHECK (json_valid (report_json)),
        report_version INTEGER NOT NULL DEFAULT 1 CHECK (report_version >= 1)
    ) STRICT;
