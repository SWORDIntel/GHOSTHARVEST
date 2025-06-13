import os
import logging
from dotenv import load_dotenv

# Initialize logger for this module
logger = logging.getLogger(__name__)

# --- Default Configurable Parameters ---
BASE_URL_PROJECT_GUTENBERG = "https://www.gutenberg.org"
CATALOG_URL_PROJECT_GUTENBERG = "https://www.gutenberg.org/cache/epub/catalog.rdf.zip" # Example, actual might differ
OUTPUT_DIR_CORPUS = "data/downloaded_corpus"
OUTPUT_DIR_PROJECT_GUTENBERG = "data/downloaded_corpus/project_gutenberg"
WG_CONFIG_DIR = "wg_configs/"
LOG_FILE_PATH = "data/logs/harvester.log"
DOWNLOADED_URLS_LOG = "data/state/downloaded_urls.log"
FAILED_URLS_LOG = "data/state/failed_urls.log"
RETRY_ATTEMPTS = 3
MAX_CONCURRENT_DOWNLOADS = 5
MIN_WAIT_BETWEEN_BOOKS_SECONDS = 10
MAX_WAIT_BETWEEN_BOOKS_SECONDS = 60

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.1.1 Safari/603.2.4",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/99.0.1150.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"
]

ARIA2C_MAX_CONNECTION_PER_SERVER = 5
ARIA2C_MIN_SPLIT_SIZE = "1M"
ARIA2C_SPLIT = 5

# --- Environment Variable Loading ---
def load_config():
    """
    Loads configuration from environment variables, falling back to defaults.
    Updates global constants with loaded values.
    """
    load_dotenv() # Load from .env file if present

    global BASE_URL_PROJECT_GUTENBERG, CATALOG_URL_PROJECT_GUTENBERG, OUTPUT_DIR_CORPUS
    global OUTPUT_DIR_PROJECT_GUTENBERG, WG_CONFIG_DIR, LOG_FILE_PATH
    global DOWNLOADED_URLS_LOG, FAILED_URLS_LOG, RETRY_ATTEMPTS, MAX_CONCURRENT_DOWNLOADS
    global MIN_WAIT_BETWEEN_BOOKS_SECONDS, MAX_WAIT_BETWEEN_BOOKS_SECONDS
    global ARIA2C_MAX_CONNECTION_PER_SERVER, ARIA2C_MIN_SPLIT_SIZE, ARIA2C_SPLIT

    logger.info("Loading configuration...")

    BASE_URL_PROJECT_GUTENBERG = os.getenv("BASE_URL_PROJECT_GUTENBERG", BASE_URL_PROJECT_GUTENBERG)
    CATALOG_URL_PROJECT_GUTENBERG = os.getenv("CATALOG_URL_PROJECT_GUTENBERG", CATALOG_URL_PROJECT_GUTENBERG)
    OUTPUT_DIR_CORPUS = os.getenv("OUTPUT_DIR_CORPUS", OUTPUT_DIR_CORPUS)
    OUTPUT_DIR_PROJECT_GUTENBERG = os.getenv("OUTPUT_DIR_PROJECT_GUTENBERG", OUTPUT_DIR_PROJECT_GUTENBERG)
    WG_CONFIG_DIR = os.getenv("WG_CONFIG_DIR", WG_CONFIG_DIR)
    LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", LOG_FILE_PATH)
    DOWNLOADED_URLS_LOG = os.getenv("DOWNLOADED_URLS_LOG", DOWNLOADED_URLS_LOG)
    FAILED_URLS_LOG = os.getenv("FAILED_URLS_LOG", FAILED_URLS_LOG)

    RETRY_ATTEMPTS = int(os.getenv("RETRY_ATTEMPTS", RETRY_ATTEMPTS))
    MAX_CONCURRENT_DOWNLOADS = int(os.getenv("MAX_CONCURRENT_DOWNLOADS", MAX_CONCURRENT_DOWNLOADS))
    MIN_WAIT_BETWEEN_BOOKS_SECONDS = int(os.getenv("MIN_WAIT_BETWEEN_BOOKS_SECONDS", MIN_WAIT_BETWEEN_BOOKS_SECONDS))
    MAX_WAIT_BETWEEN_BOOKS_SECONDS = int(os.getenv("MAX_WAIT_BETWEEN_BOOKS_SECONDS", MAX_WAIT_BETWEEN_BOOKS_SECONDS))

    ARIA2C_MAX_CONNECTION_PER_SERVER = int(os.getenv("ARIA2C_MAX_CONNECTION_PER_SERVER", ARIA2C_MAX_CONNECTION_PER_SERVER))
    ARIA2C_MIN_SPLIT_SIZE = os.getenv("ARIA2C_MIN_SPLIT_SIZE", ARIA2C_MIN_SPLIT_SIZE)
    ARIA2C_SPLIT = int(os.getenv("ARIA2C_SPLIT", ARIA2C_SPLIT))

    # Note: USER_AGENTS list is not typically loaded via a single env var,
    # but could be if serialized (e.g., comma-separated). For now, it uses the default.

    logger.info("Configuration loaded.")

# --- Runtime Update Mechanism ---
runtime_configurable_parameters = {
    "MIN_WAIT_BETWEEN_BOOKS_SECONDS": (int, lambda val: globals().update({"MIN_WAIT_BETWEEN_BOOKS_SECONDS": val})),
    "MAX_WAIT_BETWEEN_BOOKS_SECONDS": (int, lambda val: globals().update({"MAX_WAIT_BETWEEN_BOOKS_SECONDS": val})),
    "MAX_CONCURRENT_DOWNLOADS": (int, lambda val: globals().update({"MAX_CONCURRENT_DOWNLOADS": val})),
    "RETRY_ATTEMPTS": (int, lambda val: globals().update({"RETRY_ATTEMPTS": val})),
    # Add other parameters here if they should be runtime configurable
}

def update_runtime_param(param_name: str, value: any):
    """
    Updates a runtime-configurable parameter.
    Args:
        param_name (str): The name of the parameter to update.
        value (any): The new value for the parameter.
    Returns:
        bool: True if update was successful, False otherwise.
    """
    if param_name in runtime_configurable_parameters:
        try:
            param_type, updater_func = runtime_configurable_parameters[param_name]
            converted_value = param_type(value)
            updater_func(converted_value)
            logger.info(f"Runtime parameter '{param_name}' updated to '{converted_value}'.")
            return True
        except ValueError:
            logger.error(f"Invalid value type for '{param_name}'. Expected {param_type}.")
            return False
        except Exception as e:
            logger.error(f"Error updating runtime parameter '{param_name}': {e}")
            return False
    else:
        logger.warning(f"Parameter '{param_name}' is not runtime configurable or does not exist.")
        return False

# --- Initial Call to Load Configuration ---
load_config()

if __name__ == '__main__':
    # Example of how to use the config and update runtime parameters
    print(f"Initial MAX_CONCURRENT_DOWNLOADS: {MAX_CONCURRENT_DOWNLOADS}")
    update_runtime_param("MAX_CONCURRENT_DOWNLOADS", "10") # Simulate update with string value
    print(f"Updated MAX_CONCURRENT_DOWNLOADS: {MAX_CONCURRENT_DOWNLOADS}")

    update_runtime_param("MAX_CONCURRENT_DOWNLOADS", 7) # Simulate update with int value
    print(f"Updated MAX_CONCURRENT_DOWNLOADS: {MAX_CONCURRENT_DOWNLOADS}")

    update_runtime_param("NON_EXISTENT_PARAM", 100)

    print(f"Log file path: {LOG_FILE_PATH}")
    print(f"User agents: {USER_AGENTS[0]}") # Print first user agent
    print(f"Aria2c split: {ARIA2C_SPLIT}")

    # To test .env loading, create a .env file in the same directory as this script (or project root)
    # Example .env content:
    # MAX_CONCURRENT_DOWNLOADS=8
    # LOG_FILE_PATH="custom_logs/harvester.log"
    # Then run this script. The initial load_config() should pick up these values.
    # Note: For this to work, the .env file must be in the CWD when the script is run,
    # or python-dotenv must be able to find it (typically project root).
    # When running as part of a larger application, ensure .env is in the project root.
    print(f"To test .env loading, create a .env file at the project root or where this script is run from.")
