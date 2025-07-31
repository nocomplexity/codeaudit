#tarfile extractall is not secure by default
import tarfile

def extract_tar_gz(file_path, extract_path):
    with tarfile.open(file_path, 'r:gz') as tar:
        tar.extractall(path=extract_path)

def extract_tar_gz(file_path, extract_path):
    with tarfile.open(file_path, 'r:gz') as donot:
        donot.extractall(path=extract_path)

class MyExtractor:
    def extractall(self, path):
        print(f"Extracting files to: {path}")

extractor = MyExtractor()
extractor.extractall("/some/directory")

def func():
    with tarfile.open('archive.tar', 'r') as tf:
        # Extract a specific file (replace 'file.txt' with actual member name)
        tf.extract('file.txt')         
        # Extract all files
        tf.extractall()
