# Syslog Parsing and Monitoring - README

## Task Overview

This project involves parsing system log files (`syslog`) to extract structured information from raw log entries. The main task is to continuously monitor the syslog file, parse each log line into JSON format, and compress the parsed logs into gzip files. This enables easier storage, querying, and analysis of system logs.

---

## Code Flow and Functionality

1. **Setup Logging**  
   The script initializes logging to record the execution flow and errors in a log file.

2. **Parsing Logs**  
   A regex pattern is compiled to parse each syslog line into components:  
   - Timestamp  
   - Hostname  
   - Module name  
   - Process ID (if available)  
   - Log message  

3. **File and Directory Checks**  
   Before processing, the script checks the accessibility of the input log file and ensures the output directory exists and is writable.

4. **Monitoring and Parsing Loop**  
   - The script keeps track of the last read position in the syslog to only read new data.  
   - It reads chunks of the log file based on a buffer size and buffers parsed entries for a configured buffer time or until a certain number of entries are collected.  
   - Parsed entries are then written to a compressed JSON file (`.json.gz`) named with the current date.

5. **Handling Log Rotation**  
   If the syslog file is rotated (reset or truncated), the script detects this and resets its position pointer to the beginning of the file.

6. **Graceful Shutdown**  
   The script handles termination signals (`SIGTERM`, `SIGINT`) to stop monitoring cleanly and log the shutdown.

---

## Running the Script

To run the log parsing script directly from the command line:

```bash
python3 syslog_monitor.py
```
- pass optional arguments for different syslog file locations, output directories, buffer sizes, and times:
  ```
  python3 syslog_monitor.py --log-file /var/log/syslog --output-dir ~/aj_task/parsed_logs --buffer-size 4096 --buffer-time 60
  ```

### Running as a Daemon using systemd
- commands to manage the daemon:
```
sudo systemctl start syslog-monitor.service
sudo systemctl status syslog-monitor.service
sudo systemctl stop syslog-monitor.service
```

### Functionality
- Buffer Size (buffer_size): Controls how much data is read from the syslog file at a time. Larger buffer sizes reduce the number of reads, improving performance but use more memory.

- Buffer Time (buffer_time): Defines how long the script buffers parsed log entries before writing them to disk. This reduces frequent I/O operations and groups writes, improving efficiency.

- Position Tracking: The script keeps track of the last read position in the log file. This allows it to continue where it left off after interruptions or script restarts.

- Handling Log Rotation: By checking if the file size has shrunk, the script detects log rotations and resets its read position accordingly to avoid missing logs.

### Commands to Access Logs
```
ls ~/aj_task/parsed_logs/
zcat ~/aj_task/parsed_logs/syslog_parsed_YYYYMMDD.json.gz | less
```
