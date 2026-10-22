
import io
import os
import re
import json
import ipaddress
import tempfile
import xml.etree.ElementTree as ET

from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify
import pandas as pd

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

records = []
filename = "No file uploaded"

ALLOWED_EXTENSIONS = {
    ".csv", ".evtx", ".json", ".jsonl", ".ndjson",
    ".txt", ".log", ".xml", ".xlsx", ".xls",
    ".tsv"
}


def detect_column(columns, keywords):
    """Find a column using normalized column names."""
    normalized_keywords = [
        str(word).lower().replace("_", " ").replace("-", " ")
        for word in keywords
    ]

    # Prefer exact matches to avoid accidentally selecting the wrong column.
    for column in columns:
        name = str(column).strip().lower()
        name = name.replace("_", " ").replace("-", " ")
        name = re.sub(r"\s+", " ", name)

        if name in normalized_keywords:
            return column

    for column in columns:
        name = str(column).strip().lower()
        name = name.replace("_", " ").replace("-", " ")
        name = re.sub(r"\s+", " ", name)

        if any(word in name for word in normalized_keywords):
            return column

    return None


def flatten_xml_element(element, prefix=""):
    """Flatten an XML element and its attributes into a dictionary."""
    result = {}

    for key, value in element.attrib.items():
        result[f"{prefix}{key}"] = value

    children = list(element)

    if not children:
        text = (element.text or "").strip()
        if text:
            result[prefix.rstrip(".")] = text
        return result

    for child in children:
        tag = child.tag.split("}")[-1]
        child_prefix = f"{prefix}{tag}."

        child_data = flatten_xml_element(child, child_prefix)

        for key, value in child_data.items():
            if key in result:
                if not isinstance(result[key], list):
                    result[key] = [result[key]]
                result[key].append(value)
            else:
                result[key] = value

    return result


def read_evtx(content):
    """Parse a Windows EVTX file using python-evtx."""
    from Evtx.Evtx import Evtx

    # The EVTX parser expects a filesystem path.
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as temp:
        temp.write(content)
        temp_path = temp.name

    try:
        parsed_rows = []

        with Evtx(temp_path) as log:
            for event_record in log.records():
                try:
                    xml_text = event_record.xml()
                    root = ET.fromstring(xml_text)
                    event_data = flatten_xml_element(root)

                    # Retain the complete event XML for detailed investigation.
                    event_data["EventXML"] = xml_text
                    event_data["RecordID"] = str(
                        event_record.record_num()
                    )
                    parsed_rows.append(event_data)

                except (ET.ParseError, ValueError, AttributeError):
                    # Keep malformed records visible instead of losing them.
                    parsed_rows.append({
                        "RecordID": str(event_record.record_num()),
                        "EventXML": event_record.xml(),
                        "Message": "Event could not be fully parsed"
                    })

        if not parsed_rows:
            raise ValueError("The EVTX file contains no readable events.")

        return pd.DataFrame(parsed_rows)

    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass


def read_xml(content):
    """Read XML logs, including Windows-style Event XML exports."""
    root = ET.fromstring(content)
    rows = []

    # Handle exported collections of events.
    children = list(root)

    if children:
        for child in children:
            rows.append(flatten_xml_element(child))
    else:
        rows.append(flatten_xml_element(root))

    return pd.DataFrame(rows)


def read_json_records(content):
    """Read JSON arrays, objects, or newline-delimited JSON."""
    text = content.decode("utf-8-sig")

    try:
        data = json.loads(text)

        if isinstance(data, list):
            return pd.json_normalize(data)

        if isinstance(data, dict):
            # Support common wrappers such as {"events": [...]}.
            for key in ("events", "records", "logs", "results", "data"):
                if isinstance(data.get(key), list):
                    return pd.json_normalize(data[key])

            return pd.json_normalize(data)

        return pd.DataFrame([{"message": str(data)}])

    except json.JSONDecodeError:
        # Try JSON Lines format.
        rows = []

        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue

            try:
                item = json.loads(line)

                if isinstance(item, dict):
                    rows.append(item)
                else:
                    rows.append({
                        "message": str(item),
                        "line": line_number
                    })

            except json.JSONDecodeError:
                raise ValueError(
                    f"Invalid JSON at line {line_number}."
                )

        if not rows:
            raise ValueError("The JSON file contains no records.")

        return pd.json_normalize(rows)


def read_text_logs(content):
    """Treat each non-empty text/log line as one record."""
    text = content.decode("utf-8-sig", errors="replace")
    rows = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()

        if line:
            rows.append({
                "Line": line_number,
                "Message": line
            })

    if not rows:
        raise ValueError("The text log contains no readable lines.")

    return pd.DataFrame(rows)


def load_file(file):
    """Choose the correct parser based on the uploaded file extension."""
    extension = os.path.splitext(file.filename or "")[1].lower()
    content = file.read()

    if not content:
        raise ValueError("The uploaded file is empty.")

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError(
            "Unsupported file format. Upload CSV, EVTX, JSON, JSONL, "
            "TXT, LOG, XML, XLSX, XLS, or TSV."
        )

    try:
        if extension == ".evtx":
            df = read_evtx(content)

        elif extension == ".csv":
            try:
                df = pd.read_csv(
                    io.BytesIO(content),
                    encoding="utf-8-sig",
                    dtype=str,
                    keep_default_na=False,
                    on_bad_lines="error"
                )
            except UnicodeDecodeError:
                df = pd.read_csv(
                    io.BytesIO(content),
                    encoding="latin-1",
                    dtype=str,
                    keep_default_na=False,
                    on_bad_lines="error"
                )

        elif extension == ".tsv":
            df = pd.read_csv(
                io.BytesIO(content),
                sep="\t",
                dtype=str,
                keep_default_na=False
            )

        elif extension in (".json", ".jsonl", ".ndjson"):
            df = read_json_records(content)

        elif extension == ".xml":
            df = read_xml(content)

        elif extension in (".xlsx", ".xls"):
            df = pd.read_excel(
                io.BytesIO(content),
                dtype=str
            )

        elif extension in (".txt", ".log"):
            df = read_text_logs(content)

        else:
            raise ValueError("Unsupported file format.")

    except ValueError:
        raise
    except Exception as exc:
        app.logger.warning(
            "File parsing failed for %s: %s",
            extension,
            exc
        )
        raise ValueError(
            f"Unable to parse this {extension} file. "
            "Check that the file is valid and not corrupted."
        ) from exc

    if df.empty:
        raise ValueError("The uploaded file contains no records.")

    if len(df.columns) == 0:
        raise ValueError("No columns or fields could be detected.")

    df.columns = [
        str(column).strip() or f"Column_{index + 1}"
        for index, column in enumerate(df.columns)
    ]

    df = df.fillna("")

    # Convert complex values into JSON-friendly strings.
    for column in df.columns:
        df[column] = df[column].map(
            lambda value: (
                json.dumps(value, ensure_ascii=False)
                if isinstance(value, (dict, list))
                else str(value)
            )
        )

    return df


def risk_score(row, columns):
    """Assign a heuristic risk score based on event content."""
    text = " ".join(
        str(row.get(column, ""))
        for column in columns
    ).lower()

    score = 10
    reasons = []

    indicators = {
        "critical": [
            "ransomware",
            "privilege escalation",
            "data exfiltration"
        ],
        "high": [
            "failed login",
            "failed logon",
            "brute force",
            "malware",
            "sql injection",
            "unauthorized",
            "port scan",
            "suspicious",
            "denied"
        ],
        "medium": [
            "warning",
            "multiple attempts",
            "unknown",
            "blocked"
        ]
    }

    if any(word in text for word in indicators["critical"]):
        score += 70
        reasons.append("Critical threat indicator")

    if any(word in text for word in indicators["high"]):
        score += 45
        reasons.append("High-risk activity detected")

    if any(word in text for word in indicators["medium"]):
        score += 20
        reasons.append("Suspicious activity indicator")

    # Add a small penalty for each public IP address found.
    for value in row.values():
        candidate = str(value).strip()

        try:
            address = ipaddress.ip_address(candidate)

            if address.is_global:
                score += 5
        except ValueError:
            continue

    score = min(score, 100)

    if score >= 70:
        level = "High"
    elif score >= 35:
        level = "Medium"
    else:
        level = "Low"

    return score, level, reasons or [
        "No strong threat indicator found"
    ]


def get_value(row, column):
    """Safely retrieve a selected field."""
    if column is None:
        return ""

    value = row.get(column, "")
    return str(value).strip()


def process_file(file):
    global records, filename

    filename = file.filename or "uploaded_file"
    records = []

    df = load_file(file)
    columns = list(df.columns)

    time_col = detect_column(columns, [
        "timestamp", "datetime", "date time",
        "event time", "time created", "time", "date",
        "system time"
    ])

    source_col = detect_column(columns, [
        "source ip", "src ip", "source address",
        "client ip", "src", "source", "origin",
        "ip address"
    ])

    destination_col = detect_column(columns, [
        "destination ip", "dest ip", "destination address",
        "dst", "target ip", "destination"
    ])

    user_col = detect_column(columns, [
        "username", "user name", "account",
        "user", "principal", "subjectusername",
        "targetusername"
    ])

    event_col = detect_column(columns, [
        "event type", "event", "action", "activity",
        "message", "description", "status",
        "process", "event id", "eventid",
        "provider name", "level display name"
    ])

    host_col = detect_column(columns, [
        "hostname", "host name", "computer",
        "device", "host", "computername"
    ])

    for index, (_, row) in enumerate(df.iterrows()):
        item = {
            str(key): str(value)
            for key, value in row.to_dict().items()
        }

        score, level, reasons = risk_score(item, columns)

        source = get_value(row, source_col)
        destination = get_value(row, destination_col)
        user = get_value(row, user_col)
        host = get_value(row, host_col)
        event = get_value(row, event_col)
        timestamp = get_value(row, time_col)

        # Extract common Windows Event XML fields when available.
        if not timestamp:
            timestamp = next(
                (
                    value for key, value in item.items()
                    if "systemtime" in key.lower()
                    or key.lower().endswith("timecreated")
                ),
                ""
            )

        if not host:
            host = next(
                (
                    value for key, value in item.items()
                    if key.lower().endswith("computer")
                ),
                ""
            )

        if not event:
            event_id = next(
                (
                    value for key, value in item.items()
                    if key.lower().endswith("eventid")
                ),
                ""
            )
            event = f"Event ID {event_id}" if event_id else ""

        if not source:
            source = host or user or f"Event {index + 1}"

        if not destination:
            destination = host or event or "Unknown entity"

        if not event:
            event = next(
                (str(value) for value in row.values
                 if str(value).strip()),
                "Log event"
            )

        records.append({
            "id": index + 1,
            "timestamp": timestamp or "Not provided",
            "source": source,
            "destination": destination,
            "user": user or "Unknown",
            "host": host or "Unknown",
            "event": event,
            "risk": score,
            "level": level,
            "reasons": reasons,
            "raw": item
        })

    return {
        "columns": columns,
        "total": len(records),
        "high": sum(r["level"] == "High" for r in records),
        "medium": sum(r["level"] == "Medium" for r in records),
        "low": sum(r["level"] == "Low" for r in records),
        "filename": filename
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({
            "error": "Choose a file first."
        }), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({
            "error": "Choose a file first."
        }), 400

    try:
        result = process_file(file)
        return jsonify(result)

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    except Exception:
        app.logger.exception("Unexpected upload processing error")
        return jsonify({
            "error": "The file could not be processed."
        }), 500


@app.route("/data")
def data():
    level = request.args.get("level", "All")
    query = request.args.get("q", "").strip().lower()

    if level not in ("All", "High", "Medium", "Low"):
        return jsonify({
            "error": "Invalid risk level."
        }), 400

    filtered = [
        record for record in records
        if (
            level == "All"
            or record["level"] == level
        )
        and query in " ".join([
            record["timestamp"],
            record["source"],
            record["destination"],
            record["user"],
            record["host"],
            record["event"],
            json.dumps(record["raw"], ensure_ascii=False)
        ]).lower()
    ]

    return jsonify({
        "records": filtered,
        "total": len(records),
        "filtered": len(filtered),
        "filename": filename
    })


@app.route("/report")
def report():
    return jsonify({
        "filename": filename,
        "generated": datetime.now(timezone.utc).isoformat(),
        "total": len(records),
        "high": sum(r["level"] == "High" for r in records),
        "medium": sum(r["level"] == "Medium" for r in records),
        "low": sum(r["level"] == "Low" for r in records),
        "records": records
    })


if __name__ == "__main__":
    app.run(debug=False)
