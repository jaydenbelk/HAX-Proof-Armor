cd path\to\your\script
python simple_antivirus.py
cd C:\path\to\your\script
python simple_antivirus.py

def scan_file(file_path):
    """Scan a file for known signatures and optionally delete it."""
    file_hash = calculate_md5(file_path)
    if file_hash in known_signatures.values():
        print(f"Malicious file detected: {file_path}")
        delete_option = input("Do you want to delete this file? (yes/no): ")
        if delete_option.lower() == "yes":
            try:
                os.remove(file_path)
                print(f"File deleted: {file_path}")
            except Exception as e:
                print(f"Error deleting file: {e}")
    else:
        print(f"File is clean: {file_path}")
import os
import hashlib

# Define known malicious file signatures (hashes)
known_signatures = {
    "eicar_test_file": "275a021bbfb6489233a8d0a1d5aada4c",  # Example hash (EICAR test file)
    # Add more known signatures here
}

def calculate_md5(file_path):
    """Calculate the MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def scan_file(file_path):
    """Scan a file for known signatures and optionally delete it."""
    file_hash = calculate_md5(file_path)
    if file_hash in known_signatures.values():
        print(f"Malicious file detected: {file_path}")
        delete_option = input("Do you want to delete this file? (yes/no): ")
        if delete_option.lower() == "yes":
            try:
                os.remove(file_path)
                print(f"File deleted: {file_path}")
            except Exception as e:
                print(f"Error deleting file: {e}")
    else:
        print(f"File is clean: {file_path}")

def scan_directory(directory_path):
    """Recursively scan a directory for malicious files."""
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path)

def main():
    print("Simple Antivirus Program")
    directory_to_scan = input("Enter the directory to scan: ")
    if os.path.isdir(directory_to_scan):
        scan_directory(directory_to_scan)
    else:
        print("Invalid directory. Please try again.")

if __name__ == "__main__":
    main()
import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

# Define known malicious file signatures (hashes)
known_signatures = {
    "eicar_test_file": "275a021bbfb6489233a8d0a1d5aada4c",  # Example hash (EICAR test file)
    # Add more known signatures here
}

def calculate_md5(file_path):
    """Calculate the MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def scan_file(file_path):
    """Scan a file for known signatures and optionally delete it."""
    file_hash = calculate_md5(file_path)
    if file_hash in known_signatures.values():
        result = messagebox.askyesno("Malicious file detected", f"Malicious file detected: {file_path}\nDo you want to delete this file?")
        if result:
            try:
                os.remove(file_path)
                messagebox.showinfo("File deleted", f"File deleted: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error deleting file: {e}")
    else:
        messagebox.showinfo("Scan result", f"File is clean: {file_path}")

def scan_directory(directory_path):
    """Recursively scan a directory for malicious files."""
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path)

def browse_directory():
    directory_path = filedialog.askdirectory()
    if directory_path:
        scan_directory(directory_path)

def main():
    root = tk.Tk()
    root.title("Simple Antivirus Program")
    root.geometry("400x200")

    label = 
