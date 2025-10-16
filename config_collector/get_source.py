import os
import requests
from concurrent.futures import ThreadPoolExecutor
from tenacity import retry, stop_after_attempt, wait_fixed

links = "sub.txt"

with open(links, "r", encoding="utf-8") as file:
    try:
        links = [line.strip() for line in file]
    except Exception as e:
        print(f"{e} \n")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))

def get(url,session, i):
    try:
        res = session.get(url, timeout=10)
        res.raise_for_status()
        os.makedirs("source", exist_ok=True)
        output = f"source/{i}.txt"
        with open(output, "w", encoding="utf-8") as file:
            file.write(res.text)
    except Exception as e:
        print(e)

session = requests.Session()

def get_source():

    with ThreadPoolExecutor(max_workers=1) as executor:
        try:
            for i, url in enumerate(links, start=1):
                if url != "":
                    executor.submit(get, url, session, i)
        except Exception as e:
            print(e)


if __name__ == "__main__":
    get_source()
