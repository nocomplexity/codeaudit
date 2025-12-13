from compression import zstd

with zstd.open("file.zst") as f:
    file_content = f.read()

data = b"Python loves fast compression!" * 10
cdata = zstd.compress(data)
print("Compressed size:", len(cdata))

restored = zstd.decompress(cdata)
print("Matches original:", restored == data)