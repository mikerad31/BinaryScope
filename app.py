import os
import tempfile

from flask import Flask, abort, render_template, request

from analyzer import (
    analyze_file,
    decode_section_characteristics,
    machine_type,
    subsystem_type,
)
from history import get_analysis, init_db, list_analyses, save_analysis

MAX_FILE_SIZE = 64 * 1024 * 1024

# Multipart form headers add bytes beyond the uploaded file size
MULTIPART_OVERHEAD = 64 * 1024

app = Flask(__name__)
app.config["MAX_FILE_SIZE"] = MAX_FILE_SIZE
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE + MULTIPART_OVERHEAD

ALLOWED_EXTENSIONS = {"exe", "dll"}

app.add_template_filter(decode_section_characteristics, "section_flags")
init_db()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.template_filter("filesize")
def format_size(size_in_bytes):
    if size_in_bytes < 1024:
        unit = "byte" if size_in_bytes == 1 else "bytes"
        return f"{size_in_bytes} {unit}"

    value = size_in_bytes
    units = ("KiB", "MiB", "GiB")

    for unit in units:
        value /= 1024

        # If it rounds to 1024 KiB, show 1 MiB instead
        if round(value, 2) < 1024 or unit == units[-1]:
            break

    return f"{value:.2f}".rstrip("0").rstrip(".") + f" {unit}"


@app.context_processor
def file_size_limit():
    return {"max_file_size": app.config["MAX_FILE_SIZE"]}


@app.errorhandler(413)
def upload_too_large(error):
    limit = format_size(app.config["MAX_FILE_SIZE"])
    message = f"File is too large. The maximum file size is {limit}."
    return render_template("index.html", error=message), 413


@app.route("/")
def index():
    return render_template("index.html")


def render_analysis(results):
    headers = results["headers"]
    return render_template(
        "results.html",
        results=results,
        filename=results["filename"],
        machine=machine_type(headers["machine"]),
        subsystem=subsystem_type(headers["subsystem"]),
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded_file = request.files.get("file")

    if uploaded_file is None or not uploaded_file.filename:
        return render_template("index.html", error="Please select a file."), 400

    filename = uploaded_file.filename

    if not allowed_file(filename):
        return (
            render_template("index.html", error="Please upload an .exe or .dll file."),
            400,
        )

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "upload.bin")
            uploaded_file.save(path)

            if os.path.getsize(path) > app.config["MAX_FILE_SIZE"]:
                abort(413)

            results = analyze_file(path)
            results["filename"] = filename
            save_analysis(results)

    except (OSError, ValueError) as error:
        return render_template("index.html", error=f"Analysis failed: {error}"), 400

    return render_analysis(results)


@app.route("/history")
def history_page():
    analyses = list_analyses()

    return render_template("history.html", analyses=analyses)


@app.route("/analyses/<int:analysis_id>")
def view_analysis(analysis_id):
    results = get_analysis(analysis_id)

    if results is None:
        abort(404)

    return render_analysis(results)
