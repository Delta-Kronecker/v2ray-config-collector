import base64
import os

def is_base64(s: str) -> bool:
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

input_file = "config/other.txt"
output_dir = "decoded_lines"

os.makedirs(output_dir, exist_ok=True)

def decode_base64():
    with open(input_file, "r", encoding="utf-8") as f_in:
        line_number = 1
        for line in f_in:
            line = line.strip()
            if not line:
                line_number += 1
                continue

            if is_base64(line):
                decoded = base64.b64decode(line).decode("utf-8", errors="ignore")
                output_path = os.path.join(output_dir, f"line_{line_number}.txt")
                with open(output_path, "w", encoding="utf-8") as f_out:
                    f_out.write(decoded)

            line_number += 1

if __name__ == "__main__":
    decode_base64()
