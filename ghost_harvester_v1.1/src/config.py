import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
# Ensure .env is in the same directory as the script that imports config, or adjust path.
# For a structure where run.sh is at root and main_harvester.py is in src/,
# load_dotenv() might need to be called from main_harvester.py or provide path.
# Assuming .env will be at the project root when run.sh is used.
dotenv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    # Fallback for cases where .env might be in current working directory (e.g. local dev)
    load_dotenv()


# --- Default Configuration Parameters ---
_CONFIG = {
    "BASE_URL": os.getenv("BASE_URL", "http://www.gutenberg.org"),
    "CATALOG_URL": os.getenv("CATALOG_URL", "https://www.gutenberg.org/files/catalog.rdf.zip"),
    # Adjusted to be relative to project root, assuming 'data' is at root.
    "OUTPUT_DIR": os.getenv("OUTPUT_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'downloaded_corpus')),
    "LOG_DIR": os.getenv("LOG_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'logs')),
    "STATE_DIR": os.getenv("STATE_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'state')),
    "TEMP_DIR": os.getenv("TEMP_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'temp')),
    "DOWNLOADED_URLS_LOG": os.getenv("DOWNLOADED_URLS_LOG", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'state', 'downloaded_urls.log')),
    "FAILED_URLS_LOG": os.getenv("FAILED_URLS_LOG", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'state', 'failed_urls.log')),
    "ARIA2C_LOG": os.getenv("ARIA2C_LOG", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'logs', 'aria2c_downloads.log')),

    "WG_CONFIG_DIR": os.getenv("WG_CONFIG_DIR", "/etc/wireguard_configs"), # Path inside Docker container
    "IP_CHECK_SERVICE": os.getenv("IP_CHECK_SERVICE", "http://ifconfig.me/ip"),

    "MAX_CONCURRENT_DOWNLOADS": int(os.getenv("MAX_CONCURRENT_DOWNLOADS", "8")),
    "MIN_WAIT_BETWEEN_BOOKS_SECONDS": int(os.getenv("MIN_WAIT_BETWEEN_BOOKS_SECONDS", "3")),
    "MAX_WAIT_BETWEEN_BOOKS_SECONDS": int(os.getenv("MAX_WAIT_BETWEEN_BOOKS_SECONDS", "10")),
    "RETRY_ATTEMPTS": int(os.getenv("RETRY_ATTEMPTS", "5")),
    "RETRY_DELAY_SECONDS": int(os.getenv("RETRY_DELAY_SECONDS", "45")),
    "IP_ROTATION_THRESHOLD_FAILURES": int(os.getenv("IP_ROTATION_THRESHOLD_FAILURES", "2")),

    "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO").upper(),

    "MIN_ALPHA_RATIO_PDF": float(os.getenv("MIN_ALPHA_RATIO_PDF", "0.85")),
}

def get_config(key: str, default=None): # Added default parameter
    """Retrieves a configuration value."""
    value = _CONFIG.get(key, default)
    if value is None and default is None and key not in _CONFIG: # only log if key truly doesn't exist and no default was provided
        logging.warning(f"Attempted to access non-existent config key: {key} with no default.")
    return value

def set_config(key: str, value):
    """Updates a configuration value at runtime."""
    if key in _CONFIG or key.isupper(): # Allow setting new config keys if they are uppercase (convention for constants)
        original_type = type(_CONFIG.get(key)) if key in _CONFIG else None
        try:
            if original_type == int:
                _CONFIG[key] = int(value)
            elif original_type == float:
                _CONFIG[key] = float(value)
            elif original_type == bool: # Handle boolean conversion
                 _CONFIG[key] = str(value).lower() in ['true', '1', 'yes', 'y']
            else:
                _CONFIG[key] = value
            logging.info(f"Configuration updated: {key} = {_CONFIG[key]}")
        except ValueError as e:
            logging.error(f"Failed to convert value '{value}' for key '{key}' to {original_type}: {e}")
    else:
        logging.warning(f"Attempted to set potentially non-standard config key: {key}. If this is intentional, ensure it's handled.")
        _CONFIG[key] = value # Allow setting it anyway but warn

def initialize_directories():
    """Ensures all necessary directories from config exist."""
    # Corrected to use the paths as defined in _CONFIG, which are now absolute or relative to project root.
    paths_to_check = [
        _CONFIG["OUTPUT_DIR"],
        _CONFIG["LOG_DIR"],
        _CONFIG["STATE_DIR"],
        _CONFIG["TEMP_DIR"],
        os.path.dirname(_CONFIG["DOWNLOADED_URLS_LOG"]), # Ensure containing folder exists
        os.path.dirname(_CONFIG["FAILED_URLS_LOG"]),   # Ensure containing folder exists
        os.path.dirname(_CONFIG["ARIA2C_LOG"]),        # Ensure containing folder exists
    ]
    for path in paths_to_check:
        if not os.path.exists(path):
            try:
                os.makedirs(path, exist_ok=True)
                logging.info(f"Created directory: {path}")
            except Exception as e:
                logging.error(f"Failed to create directory {path}: {e}")

    # Also ensure project gutenberg and openstax subdirectories exist within OUTPUT_DIR
    project_gutenberg_path = os.path.join(_CONFIG["OUTPUT_DIR"], "project_gutenberg")
    openstax_path = os.path.join(_CONFIG["OUTPUT_DIR"], "openstax")

    if not os.path.exists(project_gutenberg_path):
        os.makedirs(project_gutenberg_path, exist_ok=True)
        logging.info(f"Created directory: {project_gutenberg_path}")

    if not os.path.exists(openstax_path):
        os.makedirs(openstax_path, exist_ok=True)
        logging.info(f"Created directory: {openstax_path}")


# Initialize directories on import
# setup_logging needs to be called from main_harvester.py AFTER config is loaded and LOG_DIR is confirmed.
# initialize_directories() also needs to be called early.
# We can call initialize_directories() here, but logging specific to this module will use default settings
# until setup_logging is called from the main application.
initialize_directories()
