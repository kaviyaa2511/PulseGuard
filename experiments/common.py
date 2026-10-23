import os

RESULTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def save_table(name, title, headers, rows):
    """Print a markdown table and save it to results/<name>.md"""
    os.makedirs(RESULTS, exist_ok=True)
    lines = [f"### {title}", "", "| " + " | ".join(headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(RESULTS, name + ".md"), "w", encoding="utf-8") as f:
        f.write(text)
    print(text)
