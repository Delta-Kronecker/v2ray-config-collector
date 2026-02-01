import os
import sys
import glob
import zipfile
import requests
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
            params = {'chat_id': chat_id, 'caption': caption, 'parse_mode': 'Markdown'}
            
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
    source_dir = "data/working_url/"
    zip_filename = "working_urls.zip"
    
    # Find all .txt files in the source directory
    file_paths = glob.glob(os.path.join(source_dir, '*.txt'))

    if not file_paths:
        print("No .txt files found in the directory to process.")
        return # Exit gracefully if there's nothing to send

    # --- Create Zip Archive ---
    try:
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in file_paths:
                zf.write(file_path, os.path.basename(file_path))
        print(f"Successfully created {zip_filename}")
    except Exception as e:
        print(f"Error creating zip file: {e}")
        sys.exit(1)

    # --- Generate Statistics Caption ---
    stats = {os.path.basename(fp): get_line_count(fp) for fp in file_paths}
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    
    # Sort stats for consistent order, placing 'all.txt' at the top if it exists
    sorted_items = sorted(stats.items(), key=lambda item: (item[0] != 'all.txt', item[0]))

    stats_lines = [f"⚡️ **V2Ray/Xray Working URLs**", f"📅 **Last Updated:** `{timestamp}`", "---"]
    for filename, count in sorted_items:
        # Format filename for Markdown (escape underscores)
        md_filename = filename.replace('_', '\\_')
        stats_lines.append(f"▫️ `{md_filename}`: **{count}** configs")
    
    total_configs = stats.get('all.txt', 0)
    stats_lines.extend(["---", f"✅ **Total Unique Configs:** **{total_configs}**"])
    
    caption = "\n".join(stats_lines)
    
    print("--- Generated Caption ---")
    print(caption)
    print("-------------------------")

    # --- Send to Telegram ---
    send_zip_to_telegram(zip_filename, caption)

if __name__ == "__main__":
    main()
