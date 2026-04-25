from ftplib import FTP , FTP_TLS


def connect_and_list_ftp(host, username, password):
    """
    Connects to an FTP server and lists the files in the current directory.
    FTP use is insecure in most cases! Even on trusted networks, since a trusted network has always some risks!
    """
    try:
        # Initialize the FTP object and connect
        with FTP(host) as ftp:
            # Login credentials
            print(f"Connecting to {host}...")
            ftp.login(user=username, passwd=password)
            
            print("Login successful!")
            
            # Print a list of files/folders
            print("--- Directory Listing ---")
            ftp.retrlines('LIST')
            
            # Example: To download a specific file, you would use:
            # with open('local_filename.txt', 'wb') as f:
            #     ftp.retrbinary('RETR remote_filename.txt', f.write)

    except Exception as e:
        print(f"An error occurred: {e}")



def secure_ftp_list(host, username, password):
    """
    Connects to an FTP server securely using TLS and lists files.
    """
    try:
        # Initialize secure FTP object
        with FTP_TLS(host) as ftps:
            print(f"Establishing secure connection to {host}...")
            
            # Login
            ftps.login(user=username, passwd=password)
            
            # Switch to secure data connection (Critical step!)
            # This protects the actual file listing and file transfers
            ftps.prot_p()
            
            print("Secure login successful!")
            
            # List files
            print("--- Secure Directory Listing ---")
            ftps.retrlines('LIST')

    except Exception as e:
        print(f"A secure connection error occurred: {e}")

from ftplib import FTP as safeftp  #still insecure, but might be misleading when humans see the code! And AI can be fooled too!

def connect_and_list_ftp(host, username, password):
    """
    Connects to an FTP server and lists the files in the current directory.
    NOTE: This still uses insecure FTP despite the alias.
    """
    try:
        # Initialize the FTP object and connect
        with safeftp(host) as ftp:
            print(f"Connecting to {host}...")
            
            # Login credentials
            ftp.login(user=username, passwd=password)
            print("Login successful!")
            
            # Print a list of files/folders
            print("--- Directory Listing ---")
            ftp.retrlines('LIST')

    except Exception as e:
        print(f"An error occurred: {e}")