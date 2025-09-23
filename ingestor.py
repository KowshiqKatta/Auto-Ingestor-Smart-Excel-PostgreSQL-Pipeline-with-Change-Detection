import os
import time
import uuid
import hashlib
import logging
import pandas as pd
import psycopg2
import psycopg2.extras
from datetime import datetime
from dateutil.parser import parse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------- CONFIG ----------
WATCH_FOLDER = r"C:\path\to\shared\folder"  # Change to your shared folder path
DB_CONFIG = {
    "dbname": "",
    "user": "",
    "password": "",
    "host": "",
    "port": ""
}
LOG_FILE = "process.log"

# ---------- LOGGING ----------
logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    format="%(message)s",
    level=logging.INFO
)
def log(msg):
    print(msg)
    logging.info(msg)

# ---------- DB CONNECTION ----------
def get_connection():
    return psycopg2.connect(**DB_CONFIG)

# ---------- HELPERS ----------
def generate_uuid():
    return str(uuid.uuid4())

def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def compute_row_hash(row):
    row_str = "|".join([str(v) if pd.notna(v) else "" for v in row])
    return hashlib.sha256(row_str.encode()).hexdigest()

def extract_metadata(file_name):
    base = os.path.basename(file_name)
    name_part = os.path.splitext(base)[0]
    parts = name_part.split("_")
    asset_id = parts[0]

    # report_type_id
    with get_connection() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute("SELECT name, report_type_id FROM report_types;")
        mapping = {r["name"]: r["report_type_id"] for r in cur.fetchall()}
    report_type_id = 0
    for key in mapping:
        if key.lower() in name_part.lower():
            report_type_id = mapping[key]
            break

    # cycle_date
    date_str = parts[1] if len(parts) > 1 else None
    cycle_date = parse(date_str, dayfirst=True).date() if date_str else None

    # cycle_no
    cycle_no = 1 if cycle_date and cycle_date.day <= 15 else 2

    # month_start
    if cycle_date:
        month_start = cycle_date.replace(day=1) if cycle_no == 1 else cycle_date.replace(day=16)
    else:
        month_start = None

    return asset_id, report_type_id, cycle_date, cycle_no, month_start

def validate_schema(df):
    expected_cols = [
        "issue_id","cves","cvss2_score","cvss2_vector","cvss3_score","cvss3_vector",
        "vulnerable_component","component_physical_p","summary","fixed_versions",
        "package_type","severity","applicability","published","provider","impacted_artifact",
        "path","impact_path","artifact_scan_time","references","description",
        "external_advisory_source","external_advisory_severity","cvss2_max_score",
        "cvss3_max_score","project_keys"
    ]
    return all(col in df.columns for col in expected_cols)

# ---------- PROCESSOR ----------
def process_file(file_path):
    try:
        log(f"File detected: {os.path.basename(file_path)}")
        df = pd.read_excel(file_path)

        if not validate_schema(df):
            with get_connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO report_metadata (report_id, asset_id, report_type_id, cycle_date, cycle_no, month_start, s3_key, csv_sha256, status, created_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (generate_uuid(), os.path.basename(file_path).split("_")[0], 0, None, None, None, "", compute_sha256(file_path), "pending", datetime.now())
                )
                conn.commit()
            log("Schema mismatch → metadata status set to pending")
            return

        asset_id, report_type_id, cycle_date, cycle_no, month_start = extract_metadata(file_path)
        report_id = generate_uuid()
        file_hash = compute_sha256(file_path)

        with get_connection() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Insert metadata
            cur.execute(
                "INSERT INTO report_metadata (report_id, asset_id, report_type_id, cycle_date, cycle_no, month_start, s3_key, csv_sha256, status, created_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (report_id, asset_id, report_type_id, cycle_date, cycle_no, month_start, "", file_hash, "ingested", datetime.now())
            )
            log(f"Metadata inserted for report_id {report_id}")

            # Track and insert rows
            inserted_count = 0
            for _, row in df.iterrows():
                row_hash = compute_row_hash(row)
                cur.execute("SELECT 1 FROM row_tracking WHERE report_id=%s AND row_hash=%s", (report_id, row_hash))
                if not cur.fetchone():
                    # Insert row into raw_report_jfrog
                    cur.execute(
                        """INSERT INTO raw_report_jfrog (
                            report_id, issue_id, cves, cvss2_score, cvss2_vector, cvss3_score, cvss3_vector,
                            vulnerable_component, component_physical_p, summary, fixed_versions, package_type,
                            severity, applicability, published, provider, impacted_artifact, path, impact_path,
                            artifact_scan_time, references, description, external_advisory_source,
                            external_advisory_severity, cvss2_max_score, cvss3_max_score, project_keys, created_at
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            report_id,
                            row.get("issue_id"), row.get("cves"), row.get("cvss2_score"), row.get("cvss2_vector"),
                            row.get("cvss3_score"), row.get("cvss3_vector"), row.get("vulnerable_component"),
                            row.get("component_physical_p"), row.get("summary"), row.get("fixed_versions"),
                            row.get("package_type"), row.get("severity"), row.get("applicability"),
                            row.get("published"), row.get("provider"), row.get("impacted_artifact"),
                            row.get("path"), row.get("impact_path"), row.get("artifact_scan_time"),
                            row.get("references"), row.get("description"), row.get("external_advisory_source"),
                            row.get("external_advisory_severity"), row.get("cvss2_max_score"),
                            row.get("cvss3_max_score"), row.get("project_keys"), datetime.now()
                        )
                    )
                    # Insert hash into row_tracking
                    cur.execute("INSERT INTO row_tracking (report_id, row_hash, last_seen) VALUES (%s,%s,%s)",
                                (report_id, row_hash, datetime.now()))
                    inserted_count += 1

            conn.commit()
            log(f"{inserted_count} rows inserted into raw_report_jfrog")

    except Exception as e:
        log(f"Error processing {file_path}: {str(e)}")

# ---------- WATCHDOG ----------
class Handler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".xlsx"):
            process_file(event.src_path)
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(".xlsx"):
            process_file(event.src_path)

def monitor_folder():
    observer = Observer()
    event_handler = Handler()
    observer.schedule(event_handler, WATCH_FOLDER, recursive=False)
    observer.start()
    log(f"Monitoring started on folder: {WATCH_FOLDER}")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# ---------- MAIN ----------
if __name__ == "__main__":
    monitor_folder()
