import gzip

content = b"Lots of content here"
with gzip.open('/home/joe/file.txt.gz', 'wb') as f:
    f.write(content)


import bz2

# Open the compressed file in read text mode ('rt')
with bz2.open("malware_example.bz2", "rt") as f:
    # Read the entire content of the file
    read_data = f.read()

print(f"Content read from the file: '{read_data}'")

