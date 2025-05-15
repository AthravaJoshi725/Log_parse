#!/usr/bin/env python3
import os
import re
import json
import gzip
import time
import argparse
import logging
import sys
import atexit
import signal
from pathlib import Path
from datetime import datetime, timedelta
# import inotify_simple


def setup_logging(log_file):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # saving the logs in file and setting format
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

    return logger

# Compile regex pattern once for efficiency
SYSLOG_PATTERN = re.compile(
    r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(?:(\w+(?:[.-]\w+)*)\[(\d+)\]:|(\w+(?:[.-]\w+)*):\s+)(.*)$'
)

def parse_syslog_line(log_line):
   # check whether log_line is empty or not string
    if not log_line or not isinstance(log_line, str):
        logging.warning(f"Invalid log line: {log_line}")
        return None

    try:
        match = SYSLOG_PATTERN.match(log_line.strip())
        if match:
            timestamp = match.group(1)
            hostname = match.group(2)

            if match.group(3) and match.group(4):
                module = match.group(3)
                pid = int(match.group(4))
                message = match.group(6)
            else:
                module = match.group(5)
                pid = None
                message = match.group(6)

            return {
                'time': timestamp,
                'hostname': hostname,
                'module': module,
                'pid': pid,
                'msg': message
            }
        else:
            logging.debug(f"Couldn't parse log line: {log_line.strip()}")
            return None

    except Exception as e:
        logging.error(f"Error parsing log line: {str(e)}")
        return None

def write_compressed_json(parsed_entries, output_file):
    if not parsed_entries:
        return

    try:
        # Use gzip compression for output
        with gzip.open(output_file, 'at') as f:
            for entry in parsed_entries:
                f.write(json.dumps(entry) + '\n')

        logging.info(f"Wrote {len(parsed_entries)} entries to {output_file}")
    except Exception as e:
        logging.error(f"Error writing output: {e}")

def check_paths(log_file_path, output_dir):
    # Check if log file exists
    if not os.path.isfile(log_file_path):
      logging.error(f"Input log file not found: {log_file_path}")
      return False

    # Check if log file is readable
    if not os.access(log_file_path, os.R_OK):
      logging.error(f"No read permission for log file: {log_file_path}")
      return False

    # Try to create output directory if it doesn't exist
    try:
      Path(output_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
      logging.error(f"Could not create output directory: {e}")
      return False

    # Check if output directory is writable
    if not os.access(output_dir, os.W_OK):
      logging.error(f"No write permission for output directory: {output_dir}")
      return False

    logging.info(f"Script has started successfully.")
    logging.info(f"Input log file: {log_file_path} is accessible.")
    logging.info(f"Output directory: {output_dir} is writable.")
    return True

def process_log_file(log_file_path, output_dir, buffer_size=4096, buffer_time=60):
    # Check whether input file and output file exist
    if not check_paths(log_file_path, output_dir):
        return

    # Create a file to track the last position
    position_file = os.path.join(output_dir, ".last_position")

    try:
        # Get file position from the last run
        position = 0
        if os.path.exists(position_file):
            try:
                with open(position_file, 'r') as f:
                    position = int(f.read().strip())
            except Exception as e:
                logging.warning(f"Could not read last position: {e}")

        # monitor the file
        while True:
            
            output_file = os.path.join(
                output_dir,
                f"syslog_parsed_{time.strftime('%Y%m%d')}.json.gz"
            )

            # Get current syslog_file size
            try:
                file_size = os.path.getsize(log_file_path)
            except FileNotFoundError:
                logging.error(f"Log file {log_file_path} not found. Waiting...")
                time.sleep(30)  # Wait before retrying
                continue

            # If file was rotated, reset position
            if position > file_size:
                logging.info("Log file was rotated, resetting position")
                position = 0

            # Read new content
            new_data_available = False
            parsed_entries = []
            buffer_start_time = time.time()

            with open(log_file_path, 'r') as f:
                f.seek(position)

                # Read chunk of content
                chunk = f.read(buffer_size)
                if chunk:
                    new_data_available = True
                    
                    for line in chunk.splitlines():
                        if line.strip():
                            parsed = parse_syslog_line(line)
                            if parsed:
                                parsed_entries.append(parsed)

                    # Update position
                    position = f.tell()


                    if len(parsed_entries) >= 1000 or (time.time() - buffer_start_time) >= buffer_time:
                        write_compressed_json(parsed_entries, output_file)
                        parsed_entries = []
                        buffer_start_time = time.time()

            if parsed_entries:
                write_compressed_json(parsed_entries, output_file)

            # Update position file
            with open(position_file, 'w') as f:
                f.write(str(position))

            
            if not new_data_available:
                time.sleep(1)  #

    except Exception as e:
        logging.error(f"Error processing log file: {e}")
        
        time.sleep(5)
def cleanup_handler():
    logging.info("Task stopped")

def main():
    parser = argparse.ArgumentParser(description='Monitor syslog and convert to JSON')
    parser.add_argument(
        '--log-file',
        default='/var/log/syslog',
        help='Path to syslog file to monitor (default: /var/log/syslog)'
    )
    parser.add_argument(
        '--output-dir',
        default=os.path.expanduser('~/aj_task/parsed_logs/'),
        help='Directory for output files (default: ~/aj_task/parsed_logs/)'
    )
    parser.add_argument(
        '--buffer-size',
        type=int,
        default=4096,
        help='Buffer size for reading (default: 4096)'
    )
    parser.add_argument(
        '--buffer-time',
        type=int,
        default=60,
        help='Time in seconds to buffer entries before writing (default: 60)'
    )
    parser.add_argument(
        '--log-file-path',
        default=os.path.join(os.path.expanduser("~"),"aj_task", "syslog_monitor.log"),
        help='Path to script log file (default: ~/syslog_monitor.log)'
    )

    args = parser.parse_args()

    logger = setup_logging(args.log_file_path)

    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))
    signal.signal(signal.SIGINT, lambda signum, frame: sys.exit(0))

    try:
        logging.info("Starting syslog monitoring service")
        process_log_file(args.log_file, args.output_dir, args.buffer_size, args.buffer_time)
    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
