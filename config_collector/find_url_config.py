import os

os.makedirs("config", exist_ok=True)

categories = [
    "ss://", "vmess://", "vless://", "trojan://",
    "ssr://", "hy://",
    "tuic://", "wireguard://",
]

def find(input_file, output_files, categories):
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                for category in categories:
                    if line.startswith(category):
                        output_files[category].write(line + "\n")
                        break
                else:
                    output_files["other.txt"].write(
                        f"From {os.path.basename(input_file)}:\n {line}\n"
                    )

    except Exception as e:
        print(f"Error processing file {input_file}: {e}")

def find_url_config():
    output_files = {}
    try:
        for cat in categories:
            output_files[cat] = open(f"config/{cat.replace('://', '')}.txt", "w", encoding="utf-8")
        output_files["other.txt"] = open("config/other.txt", "w", encoding="utf-8")

        for file in os.listdir("source"):
            if file.endswith(".txt"):
                find(os.path.join("source", file), output_files, categories)
    finally:
        for f in output_files.values():
            f.close()

if __name__ == "__main__":
    find_url_config()
