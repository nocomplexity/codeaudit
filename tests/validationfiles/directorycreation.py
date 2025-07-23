import os


def create_directory(path):
    """
    Create a directory at the specified path, including any necessary parent directories.
    If the directory already exists, do nothing.
    """
    try:
        os.makedirs(path, exist_ok=True)
        print(f"Directory created or already exists: {path}")
    except Exception as e:
        print(f"Error creating directory {path}: {e}")



def create_single_directory(path):
    """
    Create a single directory at the specified path.
    Raises an error if the directory already exists or if parent directories are missing.
    """
    try:
        os.mkdir(path)
        print(f"Directory created: {path}")
    except FileExistsError:
        print(f"Directory already exists: {path}")
    except FileNotFoundError:
        print(f"Parent directory does not exist: {path}")
    except Exception as e:
        print(f"Error creating directory {path}: {e}")


def create_fifo(fifo_path):
    """
    Creates a named pipe (FIFO) at the specified path.

    Args:
        fifo_path (str): The path where the FIFO will be created.

    Returns:
        bool: True if the FIFO was created successfully or already exists,
              False otherwise.
    """
    try:
        os.mkfifo(fifo_path)
        print(f"FIFO '{fifo_path}' created successfully.")
        return True
    except FileExistsError:
        print(f"FIFO '{fifo_path}' already exists.")
        return True
    except OSError as e:
        print(f"Error creating FIFO '{fifo_path}': {e}")
        return False


def create_file(path):
    """
    Create an empty file at the specified path using os.mknod.
    Works only on Unix-like systems and requires appropriate permissions.
    """
    try:
        os.mknod(path)
        print(f"File created: {path}")
    except FileExistsError:
        print(f"File already exists: {path}")
    except PermissionError:
        print(f"Permission denied: {path}")
    except Exception as e:
        print(f"Error creating file {path}: {e}")



def create_directories(path):
    """
    Create a directory and all necessary parent directories using os.makedirs.
    Does nothing if the directory already exists.
    """
    try:
        os.makedirs(path, exist_ok=True)
        print(f"Directory created or already exists: {path}")
    except Exception as e:
        print(f"Error creating directory {path}: {e}")
