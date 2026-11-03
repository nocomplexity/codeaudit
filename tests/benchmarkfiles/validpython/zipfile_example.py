# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


# sast_meta data
SAST_META = {
    "title": "Path Traversal via Zipfile Extraction (Zip Slip)",
    "cwe_id": [22, 59,409],   # 22 Path Traversal, 59 Improper Link Resolution Before File Access ('Link Following')
    "weakness": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "owasp": "A01:2025 - Broken Access Control",
    "severity": "High",
    "cvss": 8.1,
    "impact": "High",
    "tags": ["zipfile", "path-traversal", "zip-slip", "arbitrary-write",
             "symlink", "archive-extraction", "shutil", "python"],
}

from compression import zstd

with zstd.open("file.zst") as f:
    file_content = f.read()

data = b"Python loves fast compression!" * 10
cdata = zstd.compress(data)
print("Compressed size:", len(cdata))

restored = zstd.decompress(cdata)
print("Matches original:", restored == data)

import zipfile
import os

def insecure_extract(zip_path, extract_to_dir):
    """
    INSECURE: This function is vulnerable to the Zip Slip attack.
    It extracts all files from a zip archive without validating their paths.
    """
    print(f"--- INSECURE EXTRACTION of {zip_path} to {extract_to_dir} ---")
    os.makedirs(extract_to_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        # This line is the vulnerability: it extracts directly without path validation.
        zip_ref.extractall(extract_to_dir)
    print("Extraction attempted (might be insecure).")


with zipfile.ZipFile('spam.zip') as myzip:
    with myzip.open('eggs.txt') as myfile:
        print(myfile.read())

import shutil
shutil.unpack_archive("example.zip", "extracted_files", format="zip", filter="data")


# Open the ZIP file in read mode
with zipfile.ZipFile('example.zip', 'r') as my_zip:
    # Extract all contents to the "extracted_files" folder
    # If the folder doesn't exist, it will be created automatically
    my_zip.extractall('extracted_files')


shutil.unpack_archive("example.zip", "extracted_files", format="zip", filter="data")

shutil.copy2("source_file.txt", "backup/source_file.txt", follow_symlinks=True)

shutil.copytree("project", "project_backup", symlinks=False, ignore=None, copy_function=shutil.copy2, ignore_dangling_symlinks=False, dirs_exist_ok=False)

shutil.chown("logs/server.log", user="admin", group="admin", dir_fd=None, follow_symlinks=True)

# This path should point to the directory you want to delete
directory_to_delete = 'path/to/your/directory'

# Use shutil.rmtree() to remove the directory and its contents
shutil.rmtree(directory_to_delete)

from shutil import copy as stealmydata 
stealmydata("source_file.txt", "backup/source_file.txt", follow_symlinks=True)

from compression import zstd

with zstd.open("file.zst") as f:
    file_content = f.read()

data = b"Python loves fast compression!" * 10
cdata = zstd.compress(data)
print("Compressed size:", len(cdata))

restored = zstd.decompress(cdata)
print("Matches original:", restored == data)