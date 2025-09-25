import os
import time
import hashlib
import uuid
import pandas as pd
import psycopg2
import psycopg2.extras
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

# ------------------- DB CONFIG -------------------
DB_CONFIG = {
    "dbname": "",
    "user": "",
    "password": "",
    "host": "",
    "port": ""
}

# ------------------- SHARED FOLDER -------------------
WATCH_FOLDER = "./shared_folder"   # Change to your shared folder path

# ------------------- EXPECTED SCHEMA -------------------
EXPECTED_COLUMNS = [
    "issue_id", "cves", "cvss2_score", "cvss2_vector", "cvss3_score", "cvss3_vector",
    "vulnerable_component", "component_physical_p", "summary", "fixed_versions",
    "package_type", "severity", "applicability", "published", "provider",
    "impacted_artifact", "path", "impact_path", "artifact_scan_time", "references",
    "description", "external_advisory_source", "external_advisory_severity",
    "cvss2_max_score", "cvss3_max_score", "project_keys"
]

# ------------------- LOGGING -------------------
def log(message: str):
    print(message)
    with open("process.log", "a") as f:
        f.write(message + "\n")

# ------------------- DB CONNECTION -------------------
def get_connection():
    return psycopg2.connect(**DB_CONFIG)

# ------------------- FILE NAME PARSING -------------------
def parse_filename(filename):
    """
    Example filename: AD 2.0.4_3-Sep-25.xlsx
    - asset_id = AD
    - cycle_date = 2025-09-03
    - cycle_no = 1 or 2 (<=15 → 1, else 2)
    - month_start = 1st if cycle 1, 16th if cycle 2
    - name_part = first token in filename (asset_id candidate)
    """
    base = os.path.splitext(filename)[0]
    parts = base.split("_")

    if len(parts) < 2:
        raise ValueError(f"Invalid filename format: {filename}")

    name_part = parts[0].split()[0]  # e.g., "AD"
    date_str = parts[1]  # e.g., "3-Sep-25"

    cycle_date = datetime.strptime(date_str, "%d-%b-%y").date()
    cycle_no = 1 if cycle_date.day <= 15 else 2
    month_start = cycle_date.replace(day=1) if cycle_no == 1 else cycle_date.replace(day=16)

    return {
        "asset_id": parts[0].split()[0],
        "name_part": name_part,
        "cycle_date": cycle_date,
        "cycle_no": cycle_no,
        "month_start": month_start
    }

# ------------------- CHECKSUM -------------------
def compute_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# ------------------- SCHEMA VALIDATION -------------------
def validate_schema(df):
    return list(df.columns) == EXPECTED_COLUMNS

# ------------------- REPORT TYPE HANDLING -------------------
def get_or_create_report_type(cur, name_part):
    cur.execute("SELECT report_type_id FROM report_types WHERE name = %s", (name_part,))
    row = cur.fetchone()
    if row:
        return row[0]

    # Not found → insert new with next id
    cur.execute("SELECT COALESCE(MAX(report_type_id), 0) + 1 FROM report_types")
    next_id = cur.fetchone()[0]
    cur.execute(
        "INSERT INTO report_types (name, report_type_id) VALUES (%s, %s) RETURNING report_type_id",
        (name_part, next_id)
    )
    return cur.fetchone()[0]

# ------------------- METADATA HANDLING -------------------
def upsert_report_metadata(conn, filename, file_hash):
    parsed = parse_filename(filename)
    cur = conn.cursor()

    report_type_id = get_or_create_report_type(cur, parsed["name_part"])

    # Check if metadata exists for this asset_id
    cur.execute("SELECT report_id, csv_sha256 FROM report_metadata WHERE asset_id = %s",
                (parsed["asset_id"],))
    row = cur.fetchone()

    if row:
        report_id, old_hash = row
        if old_hash == file_hash:
            log(f"File skipped (no changes detected): {filename}")
            return None  # No change
        # Update existing
        cur.execute("""
            UPDATE report_metadata
            SET report_type_id=%s, cycle_date=%s, cycle_no=%s,
                month_start=%s, csv_sha256=%s, status=%s, created_at=NOW()
            WHERE report_id=%s
        """, (report_type_id, parsed["cycle_date"], parsed["cycle_no"],
              parsed["month_start"], file_hash, "ingested", report_id))
        conn.commit()
        log(f"Metadata updated for report_id {report_id}")
        return report_id
    else:
        # Insert new
        report_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO report_metadata
            (report_id, asset_id, report_type_id, cycle_date, cycle_no,
             month_start, s3_key, csv_sha256, status, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
        """, (report_id, parsed["asset_id"], report_type_id,
              parsed["cycle_date"], parsed["cycle_no"],
              parsed["month_start"], "", file_hash, "ingested"))
        conn.commit()
        log(f"Metadata inserted for report_id {report_id}")
        return report_id

# ------------------- ROW HASH -------------------
def compute_row_hash(row):
    row_str = "|".join([str(v) if pd.notna(v) else "" for v in row])
    return hashlib.sha256(row_str.encode()).hexdigest()

# ------------------- DATA INSERTION -------------------
def insert_rows(conn, df, report_id):
    cur = conn.cursor()

    # get max raw_id
    cur.execute("SELECT COALESCE(MAX(raw_id),0) FROM raw_report_jfrog")
    start_id = cur.fetchone()[0] + 1
    raw_id = start_id

    new_count = 0
    for _, row in df.iterrows():
        row_hash = compute_row_hash(row)
        # Check if already in row_tracking
        cur.execute("""
            SELECT 1 FROM row_tracking WHERE report_id=%s AND row_hash=%s
        """, (report_id, row_hash))
        if cur.fetchone():
            continue  # already ingested

        values = [row.get(col) for col in EXPECTED_COLUMNS]
        cur.execute(f"""
            INSERT INTO raw_report_jfrog
            (raw_id, report_id, {",".join(EXPECTED_COLUMNS)}, created_at)
            VALUES (%s,%s,{",".join(['%s']*len(EXPECTED_COLUMNS))}, NOW())
        """, [raw_id, report_id] + values)

        # Insert into row_tracking
        cur.execute("""
            INSERT INTO row_tracking (report_id, row_hash, last_seen)
            VALUES (%s,%s,NOW())
        """, (report_id, row_hash))

        raw_id += 1
        new_count += 1

    conn.commit()
    if new_count > 0:
        log(f"{new_count} rows inserted into raw_report_jfrog for report_id {report_id}")
    else:
        log(f"No new rows to insert for report_id {report_id}")

# ------------------- PROCESS FILE -------------------
def process_file(filepath):
    conn = get_connection()
    try:
        filename = os.path.basename(filepath)
        file_hash = compute_file_hash(filepath)
        df = pd.read_excel(filepath)

        # validate schema
        if not validate_schema(df):
            cur = conn.cursor()
            parsed = parse_filename(filename)
            cur.execute("""
                INSERT INTO report_metadata
                (report_id, asset_id, report_type_id, cycle_date, cycle_no,
                 month_start, s3_key, csv_sha256, status, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
            """, (str(uuid.uuid4()), parsed["asset_id"], 0,
                  parsed["cycle_date"], parsed["cycle_no"],
                  parsed["month_start"], "", file_hash, "pending"))
            conn.commit()
            log(f"Schema mismatch, metadata marked as pending for file {filename}")
            return

        # metadata handling
        report_id = upsert_report_metadata(conn, filename, file_hash)
        if not report_id:
            return  # skipped

        # insert rows
        insert_rows(conn, df, report_id)

    finally:
        conn.close()

# ------------------- FILE WATCHER -------------------
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
    log("Monitoring started...")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    monitor_folder()
