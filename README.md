# 📂 Smart Excel-to-Postgres Pipeline with Watchdog Automation

## 📖 Overview  
This project is a **Python-based automated pipeline** that monitors a shared folder for Excel files and smartly syncs them into a **PostgreSQL database**.  

Unlike naive ingestion scripts that reprocess everything on each change, this solution:  
- Handles **real-time file monitoring**  
- Tracks **metadata consistency**  
- Prevents **duplicate/unnecessary processing**  
- Supports **incremental updates** when rows are added  
- Logs all important events with clean & simple messages  

It’s designed with **team workflows** in mind — where multiple users might open, edit, or re-save files, even with no real changes.  

---

## ⚡ Key Features  
- ✅ Monitors a folder continuously for `.xlsx` files  
- ✅ Automatically detects new or modified files  
- ✅ Loads only **changed rows** (not the entire file again)  
- ✅ Maintains a **report metadata table** in sync with file info  
- ✅ Ignores files that are opened & saved without actual changes  
- ✅ Updates metadata when details (like dates in filenames/sheet names) change  
- ✅ Uses **row-level hashing** for deduplication  
- ✅ Logs every action (plain, minimal, and readable logs)  

---

## 🛠️ Technologies Used  
- 🐍 Python  
- 📊 Pandas (Excel reading & DataFrames)  
- 🐘 Psycopg2 (PostgreSQL connection)  
- 👀 Watchdog (filesystem monitoring)  
- 🔑 Hashlib (row-level deduplication with SHA256 hashes)  
- 📝 Logging (simple log tracking)  

---

## 🔍 Corner Cases Handled  
This script isn’t just about "happy path" ingestion — it takes care of tricky real-world scenarios:  

1. **Unchanged File Re-Save**  
   - If a user opens a file and re-saves it without changes, the file will **not** be reprocessed.  

2. **Changed Metadata (File/Sheet Names)**  
   - If the file/sheet name changes (e.g., date changed in name), the **report_metadata table** is updated automatically.  

3. **New Rows Added**  
   - If extra rows are added to an existing file, **only the new rows** are inserted into the DB.  

4. **Duplicate Row Prevention**  
   - Re-saved or re-uploaded files won’t create duplicate data in the DB.  

5. **Partial Edits with Revert**  
   - If a row is edited and reverted back, no unnecessary DB operations occur.  

6. **Simultaneous Users**  
   - Multiple users can open/edit the file — only real changes are processed.  

---

## 📂 Database Structure  

**1. `raw_report_jfrog`**  
- Stores the actual Excel row data.  
- Deduplication is ensured using **row-level SHA256 hashes** (handled internally, not extra columns in DB).  

**2. `report_metadata`**  
- Tracks details about each file (name, sheet, date, etc.).  
- Automatically updated when metadata changes.  

---

## ▶️ How It Works  
1. Place Excel files in the **watched folder**  
2. Script (via **Watchdog**) detects file creation or modification  
3. File contents are read using **Pandas**  
4. Each row is hashed (SHA256) → prevents duplicates  
5. New rows are inserted into `raw_report_jfrog`  
6. Metadata is inserted/updated in `report_metadata`  
7. Plain logs are written for each action  

