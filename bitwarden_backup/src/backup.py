import json
import logging
import os
import subprocess

from auth import login, logout
from encryption import encrypt_data, decrypt_data

logger = logging.getLogger(__name__)

def validate_file(file_path: str) -> bool:
    """
    Validates that the given file exists and is not empty and is a valid json file.
    Args:
        file_path (str): The path to the file to validate.

    Returns:
        int: 0 if the file is invalid, otherwise the number of items in the JSON array.
    """
    if not os.path.isfile(file_path):
        logger.error(f"File does not exist: {file_path}")
        return 0
    if os.path.getsize(file_path) == 0:
        logger.error(f"File is empty: {file_path}")
        return 0

    with open(file_path, 'r') as f:
        try:
            file_content = decrypt_data(f.read().encode())
        except Exception as e:
            logger.error(f"Decryption failed for file {file_path}: {e}")
            return 0
        try:
            file_object = json.loads(file_content)
        except json.JSONDecodeError:
            logger.error(f"File is not valid JSON: {file_path}")
            return 0
        
    if not file_object['items'] or len(file_object['items']) == 0:
        logger.error(f"Expected JSON object to be a non-empty array. Found empty array in file: {file_path}")
        return 0
    return len(file_object['items'])

def validate_backups(backup_dir: str) -> int:
    """
    Validates the backup files in the backup directory.
    Returns:
        int: The number of items in the most recent valid backup file.
    Raises:
        FileNotFoundError: If the backup directory does not exist or no valid backup files are found.
    """
    try:
        most_recent_item_count = -1
        files = [os.path.join(backup_dir, f) for f in os.listdir(backup_dir) if os.path.isfile(os.path.join(backup_dir, f))]
        if not files:
            logger.warning("No backup files found.")
        else:
            files = sorted(files, key=os.path.getctime)
            for file in files:
                item_count = validate_file(file)
                if item_count == 0:
                    logger.warning(f"Found invalid backup file: {file}")
                else:
                    most_recent_item_count = item_count
                    logger.debug(f"Found valid backup file: {file} with {item_count} items")
            if most_recent_item_count == -1:
                logger.error(f"Found length {len(files)} backup files but none are valid.")
                raise FileNotFoundError("No valid backup files found.")
            if len(files) > 4:
                os.remove(files[0])
                logger.info(f"Deleted oldest backup file: {files[0]}")

        return most_recent_item_count
    except Exception as e:
        logger.error(f"Error validating backups: {e}")
        raise

def get_backup_data(previous_item_count: int = -1, encryption_password: str = "") -> bytes:
    """
    Exports data from Bitwarden, encrypts it, and returns the encrypted data.
    Returns:
        bytes: The encrypted backup data.
    """
    try:
        session = login()
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise

    try:
        export_process = subprocess.Popen(["bw", "export", "--raw", "--format", "json", "--session", session], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        data, _ = export_process.communicate()
        logout()
        if data is None or data.strip() == b'':
            logger.error("No data exported from Bitwarden.")
            raise Exception("Exported data is empty.")
        
        item_count = len(json.loads(data).get('items', []))

        if previous_item_count != -1 and abs(item_count - previous_item_count) > 25:
            logger.warning(f"Item count {item_count} differs significantly from previous count {previous_item_count}. Possible data integrity issue.")
        
        encrypted_data = encrypt_data(data)
        return encrypted_data
    
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        raise

def check_environment():
    required_vars = ["BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD", "ENCRYPTION_PASSWORD", "BACKUP_DIR"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        raise EnvironmentError(f"Missing environment variables: {', '.join(missing_vars)}")
    else:
        logger.info("All required environment variables are set.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        logger.info("Starting Bitwarden backup process.")
        check_environment()
        backup_dir = os.getenv("BACKUP_DIR", "/backups")
        encryption_password = os.getenv("ENCRYPTION_PASSWORD")

        bitwarden_backup_dir = os.path.join(backup_dir, "bitwarden")
        os.makedirs(bitwarden_backup_dir, exist_ok=True)

        previous_item_count = validate_backups(bitwarden_backup_dir)
        encrypted_data = get_backup_data(previous_item_count, encryption_password)
        backup_file_path = os.path.join(bitwarden_backup_dir, f"bitwarden_backup_{int(os.path.getmtime(bitwarden_backup_dir))}.enc")
        with open(backup_file_path, 'wb') as backup_file:
            backup_file.write(encrypted_data)
        logger.info(f"Backup completed and saved to {backup_file_path}")
    except Exception as e:
        logger.error(f"Backup process failed: {e}")
        exit(3)
