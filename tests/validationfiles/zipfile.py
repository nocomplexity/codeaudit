from zipfile import ZipFile

def insecure_extract(zip_path, extract_to_dir):
    """
    INSECURE: This function is vulnerable to the Zip Slip attack.
    It extracts all files from a zip archive without validating their paths.
    """       
    with ZipFile(zip_path, 'r') as zip_ref:
        # This line is the vulnerability: it extracts directly without path validation.
        zip_ref.extractall(extract_to_dir)
    print("Extraction attempted (might be insecure).")
    
    with ZipFile('spam.zip','r') as myzip:
        with myzip.open('eggs.txt') as myfile:
            print(myfile.read())

    with ZipFile('example.zip') as zf:
        with zf.open('file_inside.txt', 'r') as file:
            content = file.read().decode('utf-8')
            print(content)

def another_function():
    with ZipFile('example.zip') as zf:
        with zf.open('file_inside.txt', 'r') as file:
            content = file.read().decode('utf-8')
            print(content)
