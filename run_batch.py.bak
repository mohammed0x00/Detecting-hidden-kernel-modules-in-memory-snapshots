import os
import sys
import gzip
import shutil
import zipfile
import tempfile
import subprocess
from pathlib import Path

# =========================
# Configuration
# =========================

ZIP_PATH = os.getenv("ZIP_PATH", "rootkit-dataset.zip")
VOLATILITY_SCRIPT = os.getenv("VOLATILITY_SCRIPT", "vol.py")
PLUGIN_PATH = os.getenv("PLUGIN_PATH", "ModXRef")
SYMTABS_PATH = os.getenv("SYMTABS_PATH", "symtabs")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "volatility_outputs")

# Folders inside the ZIP to search
TARGET_PREFIXES = [
    "rootkit-dataset/dumps/wild/",
    "rootkit-dataset/dumps/open/",
]

# Volatility command template
# Equivalent to:
# python vol.py -p ModXRef -s symtabs/ -f thor.ko.elf mod_xref --vma
def build_command(elf_path: str):
    return [
        sys.executable,
        VOLATILITY_SCRIPT,
        "-p", PLUGIN_PATH,
        "-s", SYMTABS_PATH,
        "-f", elf_path,
        "mod_xref",
        "--vma",
    ]


def is_target_gz(zip_member_name: str) -> bool:
    """Return True if the ZIP entry is a .gz file inside one of the target folders."""
    normalized = zip_member_name.replace("\\", "/")
    return (
        any(normalized.startswith(prefix) for prefix in TARGET_PREFIXES)
        and normalized.endswith(".gz")
    )


def safe_output_name(zip_member_name: str) -> str:
    """
    Create a safe output filename based on the ZIP member path.
    Example:
    rootkit-dataset/dumps/wild/thor.ko.elf.gz
    -> wild__thor.ko.elf.txt
    """
    normalized = zip_member_name.replace("\\", "/")
    parts = normalized.split("/")

    folder_name = "unknown"
    if "wild" in parts:
        folder_name = "wild"
    elif "open" in parts:
        folder_name = "open"

    base_name = Path(parts[-1]).name  # e.g. thor.ko.elf.gz
    if base_name.endswith(".gz"):
        base_name = base_name[:-3]  # remove .gz

    return f"{folder_name}__{base_name}.txt"


def extract_gz_from_zip_to_temp(zip_file: zipfile.ZipFile, member_name: str, temp_dir: str) -> str:
    """
    Read a .gz file directly from the ZIP and decompress it into a temp .elf file.
    Returns the path to the decompressed .elf file.
    """
    gz_filename = Path(member_name).name  # e.g. thor.ko.elf.gz
    elf_filename = gz_filename[:-3] if gz_filename.endswith(".gz") else gz_filename
    elf_path = os.path.join(temp_dir, elf_filename)

    with zip_file.open(member_name) as zipped_gz_stream:
        with gzip.GzipFile(fileobj=zipped_gz_stream) as gz_stream:
            with open(elf_path, "wb") as out_f:
                shutil.copyfileobj(gz_stream, out_f)

    return elf_path


def run_volatility(elf_path: str) -> subprocess.CompletedProcess:
    """Run the volatility command on the given ELF file."""
    cmd = build_command(elf_path)
    print(f"[+] Running: {' '.join(cmd)}")
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if not os.path.isfile(ZIP_PATH):
        print(f"[ERROR] ZIP file not found: {ZIP_PATH}")
        sys.exit(1)

    if not os.path.isfile(VOLATILITY_SCRIPT):
        print(f"[ERROR] Volatility script not found: {VOLATILITY_SCRIPT}")
        sys.exit(1)

    if not os.path.isdir(SYMTABS_PATH):
        print(f"[ERROR] symtabs directory not found: {SYMTABS_PATH}")
        sys.exit(1)

    with zipfile.ZipFile(ZIP_PATH, "r") as zf:
        members = [name for name in zf.namelist() if is_target_gz(name)]

        if not members:
            print("[WARNING] No matching .gz files found in the target folders.")
            return

        print(f"[+] Found {len(members)} .gz files to process.")

        for index, member in enumerate(members, start=1):
            print(f"\n[{index}/{len(members)}] Processing: {member}")

            with tempfile.TemporaryDirectory() as temp_dir:
                try:
                    # Step 1: extract/decompress one ELF at a time
                    elf_path = extract_gz_from_zip_to_temp(zf, member, temp_dir)
                    print(f"[+] Decompressed to: {elf_path}")

                    # Step 2: run volatility
                    result = run_volatility(elf_path)

                    # Step 3: save output
                    output_file = os.path.join(OUTPUT_DIR, safe_output_name(member))
                    with open(output_file, "w", encoding="utf-8", errors="replace") as f:
                        f.write(f"ZIP member: {member}\n")
                        f.write(f"Extracted ELF: {elf_path}\n")
                        f.write(f"Return code: {result.returncode}\n")
                        f.write("=" * 80 + "\n")
                        f.write("STDOUT\n")
                        f.write("=" * 80 + "\n")
                        f.write(result.stdout or "")
                        f.write("\n\n")
                        f.write("=" * 80 + "\n")
                        f.write("STDERR\n")
                        f.write("=" * 80 + "\n")
                        f.write(result.stderr or "")

                    print(f"[+] Saved output to: {output_file}")

                except Exception as e:
                    error_file = os.path.join(OUTPUT_DIR, safe_output_name(member))
                    with open(error_file, "w", encoding="utf-8", errors="replace") as f:
                        f.write(f"ZIP member: {member}\n")
                        f.write("Status: FAILED\n")
                        f.write(f"Error: {e}\n")

                    print(f"[ERROR] Failed processing {member}: {e}")

    print("\n[+] Done.")


if __name__ == "__main__":
    main()