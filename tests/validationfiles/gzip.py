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

#now with the class function
with bz2.BZ2File("demo.bz2", mode='r') as f:
    content = f.read()

import lzma

# Data to be compressed
data = b"This is a test string that will be compressed using LZMA."
compressed_filename = "example.xz"

print(f"Original data: {data}\n")

# Compress and write data to a file
with lzma.open(compressed_filename, 'wb') as f:
    f.write(data)

print("Data has been compressed and written to 'example.xz'.")

# Decompress and read data from the file
with lzma.open(compressed_filename, 'rb') as f:
    decompressed_data = f.read()

print(f"Decompressed data: {decompressed_data}")

# You would need to manually delete 'example.xz' after running this code.

#Reading using lzma.LZMAFILE class


with lzma.LZMAFile("demo.xz", mode='r') as f:
    content = f.read()

print(f"Content read from the file: {content.decode()}")

