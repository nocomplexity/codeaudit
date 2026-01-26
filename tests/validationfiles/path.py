from pathlib import Path

def read_user_file(filename):
    # The developer intends to read files from the 'uploads' folder
    base_path = Path("uploads/")
    
    # Insecure: Directly joining user input with the base path
    target_path = base_path / filename
    
    # Using Path.open() to return the content
    with target_path.open("r") as file:
        return file.read()
    
p = Path('setup.py')
with p.open() as f:
    f.readline()


# One-liner to open, read, and close a file
content = Path("example.txt").open().read()


content2 = Path("file.txt").read_text()

p2 = Path('my_binary_file')
p2.write_bytes(b'Binary file contents')

p4.read_bytes()