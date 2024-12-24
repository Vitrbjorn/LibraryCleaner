import os
import hashlib

def create_hash_file_in_target(target_folder):
    """Create a hash file in the target directory to store unique file hashes.
    If the file does not exist, it will be created.

    Args:
        target_folder (str): The path to the target folder where the hash file will be created.

    Returns:
        str: The path to the hash file where hashes are stored.
    """
    hash_file = os.path.join(target_folder, 'hashes.txt')
    if not os.path.isfile(hash_file):
        with open(hash_file, 'w') as f:
            pass  # Create an empty file if it doesn't exist
    return hash_file

def compute_file_hash(file_path):
    """Generate an SHA-256 hash for a file.
    This function reads the file in chunks to handle large files efficiently.

    Args:
        file_path (str): The path to the file to be hashed.

    Returns:
        str: The SHA-256 hash of the file as a hexadecimal string, or None if an error occurs.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):  # Read the file in 8KB chunks
                sha256.update(chunk)
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return None
    return sha256.hexdigest()

def load_existing_hashes(hash_file):
    """Load existing hashes from the hash file.

    Args:
        hash_file (str): The path to the hash file.

    Returns:
        set: A set containing all the hashes stored in the file.
    """
    hashes = set()
    try:
        with open(hash_file, 'r') as f:
            hashes = {line.strip() for line in f}  # Read each hash into a set
    except FileNotFoundError:
        pass  # If the file doesn't exist, return an empty set
    return hashes

def add_hash_to_file(hash_file, file_hash):
    """Add a new hash to the hash file.

    Args:
        hash_file (str): The path to the hash file.
        file_hash (str): The hash value to be added.
    """
    with open(hash_file, 'a') as f:
        f.write(file_hash + '\n')  # Append the new hash to the file

def process_target_folder(target_folder, hash_file):
    """Search the target folder and its subfolders, deduplicating files based on hash values.
    If a file's hash is not in the hash file, it is added. If it is already present, the file is deleted.

    Args:
        target_folder (str): The path to the folder to be processed.
        hash_file (str): The path to the hash file.
    """
    existing_hashes = load_existing_hashes(hash_file)  # Load existing hashes from the file
    for root, _, files in os.walk(target_folder):  # Recursively walk through the target folder
        for file in files:
            if file == 'hashes.txt':
                continue  # Skip the hash file itself
            file_path = os.path.join(root, file)  # Full path of the current file
            file_hash = compute_file_hash(file_path)  # Generate the hash of the file

            if file_hash is None:  # Skip files that couldn't be hashed
                continue

            if file_hash in existing_hashes:
                print(f"Duplicate found. Deleting file: {file_path}")
                os.remove(file_path)  # Delete the duplicate file
            else:
                print(f"New file detected. Adding hash: {file_hash}")
                existing_hashes.add(file_hash)  # Add the hash to the set
                add_hash_to_file(hash_file, file_hash)  # Save the new hash to the file

def main():
    """Main function to execute the deduplication process.
    Prompts the user for the target folder path, then processes the folder.
    """
    target_folder = input("Enter the path for the target folder to deduplicate: ").strip()

    if not os.path.exists(target_folder):
        print("Error: Target folder does not exist.")
        return

    hash_file = create_hash_file_in_target(target_folder)  # Create or load the hash file in the target folder
    process_target_folder(target_folder, hash_file)  # Deduplicate files in the target folder

if __name__ == "__main__":
    main()  # Run the program
