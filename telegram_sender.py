import os
import sys
import glob
import zipfile
import requests
import time
from datetime import datetime

def get_line_count(file_path):
    """Counts non-empty lines in a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return len([line for line in f if line.strip()])
    except Exception:
        return 0

def send_zip_to_telegram(zip_path, caption):
    """Sends a zip file to a Telegram channel with a caption."""
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not bot_token or not chat_id:
        print("Error: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables are not set.")
        sys.exit(1)

    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    
    try:
        with open(zip_path, 'rb') as f:
            files = {'document': (os.path.basename(zip_path), f)}
            params = {'chat_id': chat_id, 'caption': caption, 'parse_mode': 'HTML'}
            
            response = requests.post(url, params=params, files=files, timeout=60)
            response.raise_for_status()
        
        print(f"Successfully sent {zip_path} to Telegram.")
    except requests.exceptions.RequestException as e:
        print(f"Error sending document to Telegram: {e}")
        if e.response:
            print(f"Response: {e.response.text}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: Zip file not found at {zip_path}")
        sys.exit(1)

def main():
    """
    Zips working URL files, generates statistics, and sends them to Telegram.
    """
    start_time = time.time()
    source_dir = "data/working_url/"
    zip_filename = "working_urls.zip"
    
    file_paths = glob.glob(os.path.join(source_dir, '*.txt'))

    if not file_paths:
        print("No .txt files found to process.")
        return

    try:
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in file_paths:
                zf.write(file_path, os.path.basename(file_path))
        print(f"Successfully created {zip_filename}")
    except Exception as e:
        print(f"Error creating zip file: {e}")
        sys.exit(1)

    stats = {os.path.basename(fp): get_line_count(fp) for fp in file_paths}
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    # --- Build the new, stylish caption using HTML for Telegram ---
    caption_lines = [
        "<b>✨ V2Ray/Xray Ultimate Collector ✨</b>",
        f"📅 <b>Date:</b> <code>{timestamp}</code>",
        "",
        f"🔍 <b>Sources Checked:</b> {len(file_paths)} files",
        "📊 <b>Stats:</b>"
    ]

    sorted_items = sorted(stats.items(), key=lambda item: (item[0] != 'all.txt', item[0]))
    
    for filename, count in sorted_items:
        if filename == 'all.txt':
            continue # Skip 'all.txt' in the detailed list
        # Use code tags for filenames to make them stand out
        caption_lines.append(f"   🔹 <code>{filename}</code>: {count}")

    caption_lines.append("-------------------------")
    
    total_configs = stats.get('all.txt', 0)
    caption_lines.append(f"✅ <b>Total Unique Configs:</b> {total_configs}")
    
    end_time = time.time()
    execution_time = round(end_time - start_time)
    caption_lines.append(f"⏱ <b>Time:</b> {execution_time}s")
    caption_lines.append("")
    caption_lines.append("<i>Attached ZIP contains all collected configuration files.</i>")

    caption = "\n".join(caption_lines)
    
    print("--- Generated Caption ---")
    print(caption)
    print("-------------------------")

    send_zip_to_telegram(zip_filename, caption)

if __name__ == "__main__":
    main()
