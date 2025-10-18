import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

def login():
    """
    Logs in to Bitwarden using the CLI and sets the BW_SESSION environment variable.
    Raises:
        EnvironmentError: If required environment variables are not set.
        subprocess.CalledProcessError: If the login or unlock command fails.
    """
    login_command = ["bw", "login", "--apikey"]
    try:
        login_result = subprocess.run(login_command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        if e.stderr and "You are already logged in" in e.stderr:
            logger.info("Already logged in to Bitwarden.")
        else:
            logger.error(f"Login failed: {e}")
            logger.error(f"stderr: {e.stderr}")
            raise        

    unlock_command = ["bw", "unlock", "--passwordenv", "BW_PASSWORD"]
    try:
        logger.info("Logged in to Bitwarden CLI.")
        unlock_result = subprocess.run(unlock_command, check=True, capture_output=True, text=True)
        session_regex = r'export BW_SESSION="(.*?)"'
        session = re.search(session_regex, unlock_result.stdout).group(1)
        if not session:
            logger.error("Failed to retrieve BW_SESSION from unlock output.")
            raise Exception("BW_SESSION not found.")
        logger.info("Logged in to Bitwarden and set BW_SESSION.")
        return session
    except subprocess.CalledProcessError as e:
        if "You are already logged in" in e.stderr:
            logger.info("Bitwarden is already unlocked.")
        else:
            logger.error(f"Unlock failed: {e}")
            logger.error(f"stderr: {e.stderr}")
            raise

def logout():
    """Locks and logs out of Bitwarden."""
    try:
        lock_command = ["bw", "lock"]
        lock_result = subprocess.run(lock_command, check=True, capture_output=True, text=True)
        if "Your vault is locked" not in lock_result.stdout:
            logger.error("Failed to lock the vault.")
            raise Exception("Locking vault failed.")

        logout_command = ["bw", "logout"]
        logout_result = subprocess.run(logout_command, check=True, capture_output=True, text=True)
        if "You have logged out" not in logout_result.stdout:
            logger.error("Failed to log out.")
            raise Exception("Logout failed.")
        
        logger.info("Logged out of Bitwarden.")
    except subprocess.CalledProcessError as e:
        if "You are not logged in" in e.stderr:
            logger.info("Already logged out of Bitwarden.")
        else:
            logger.error(f"Lock failed: {e}")
            raise
        