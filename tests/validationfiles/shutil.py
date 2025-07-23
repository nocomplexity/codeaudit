import shutil

shutil.unpack_archive("example.zip", "extracted_files", format="zip", filter="data")

shutil.copy2("source_file.txt", "backup/source_file.txt", follow_symlinks=True)

shutil.copytree("project", "project_backup", symlinks=False, ignore=None, copy_function=shutil.copy2, ignore_dangling_symlinks=False, dirs_exist_ok=False)

shutil.chown("logs/server.log", user="admin", group="admin", dir_fd=None, follow_symlinks=True)


from shutil import copy as stealmydata 
stealmydata("source_file.txt", "backup/source_file.txt", follow_symlinks=True)
