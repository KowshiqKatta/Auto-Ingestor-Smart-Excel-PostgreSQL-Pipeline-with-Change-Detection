# Auto Ingestor: Smart Excel → PostgreSQL Pipeline with Change Detection

🚀 A production-ready Python pipeline that **automatically detects new or updated Excel reports in a shared folder** and ingests them into PostgreSQL with **zero duplicates** and **robust metadata tracking**.  

This project goes beyond basic ETL — it **watches a folder in real-time**, validates schemas, tracks metadata, computes checksums, detects row-level changes, and handles corner cases gracefully.  

---

## ✨ Features

- 📂 **Folder Watcher** – constantly monitors a shared folder for new/modified Excel files.  
- 🧾 **Metadata Tracking** – every report gets a unique `report_id` and detailed metadata record in `report_metadata`.  
- 🔒 **Schema Validation** – if the Excel schema doesn’t match expectations, ingestion is blocked and metadata is marked as `pending`.  
- 🧮 **Smart Row Deduplication** – only new or changed rows are inserted into `raw_report_jfrog`, thanks to a hash-based row tracking mechanism (`row_tracking` table).  
- ⚡ **Efficient Change Detection** – resaving a file without changes won’t trigger re-ingestion.  
- 🛠 **Metadata Updates** – if the file name changes (e.g., new cycle date), corresponding metadata gets updated automatically.  
- 🗄 **PostgreSQL Integration** – designed with `psycopg2` and `pandas` for seamless DB + Excel handling.  
- 📜 **Concise Logging** – clear logs both in console and `process.log` for quick debugging.  

---

## 🧩 Concepts Used

- **Watchdog** → For real-time folder monitoring.  
- **PostgreSQL** → Persistent storage for metadata + row-level data.  
- **UUIDs** → Each report gets a globally unique ID.  
- **SHA256 Checksums** → File integrity + row-level change detection.  
- **Schema Validation** → Guards against wrong or incomplete data.  
- **Row Hashing + Tracking Table** → Ensures only new rows are inserted, preventing duplicates.  
- **ETL Pattern** → Extract (Excel) → Transform (metadata/validation) → Load (Postgres).  

---

## 🔍 Corner Cases Handled

✅ Schema mismatch → Report metadata stored with `pending` status, ingestion skipped.  
✅ File re-saved with no changes → Skipped (no duplicate processing).  
✅ Metadata-only changes (e.g., file date/asset ID in filename) → Metadata updated accordingly.  
✅ Row additions/edits → Only new or modified rows are inserted.  
✅ Old rows preserved → Because row hashes prevent duplication.  
✅ Safe re-runs → Script is idempotent; running multiple times won’t cause duplicate inserts.  
✅ Fail-safe logging → Every step (detected, skipped, ingested, updated) is logged clearly.  

---

## ⚙️ Setup

### 1. Clone the repo
```bash
git clone https://github.com/<your-username>/auto-ingestor.git
cd auto-ingestor
