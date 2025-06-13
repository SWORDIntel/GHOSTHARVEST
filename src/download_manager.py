import asyncio
import os
import logging
import shlex # For safely formatting shell commands
from typing import Set, Optional

# Attempt to import actual project modules
try:
    from src import utils
    from src import config
    from src import ip_rotator
    from src import text_converter
except ImportError:
    # Mock objects for standalone testing or linting
    logging.warning("Using mock objects for src.utils, src.config, src.ip_rotator, src.text_converter.")

    class MockUtils:
        async def read_file_async(self, path: str, encoding: str = "utf-8") -> Optional[str]:
            if not os.path.exists(path): return None
            try:
                with open(path, "r", encoding=encoding) as f: return f.read()
            except Exception as e:
                logging.error(f"MockUtils.read_file_async error: {e}")
                return None

        async def append_to_file_async(self, path: str, content: str, encoding: str = "utf-8") -> bool:
            try:
                with open(path, "a", encoding=encoding) as f: f.write(content + "\n")
                return True
            except Exception as e:
                logging.error(f"MockUtils.append_to_file_async error: {e}")
                return False

        async def run_command(self, command: str) -> tuple[bool, str]:
            logging.info(f"MockUtils.run_command: Simulating execution of: {command}")
            # Simulate success for specific commands if needed for testing flow
            if "aria2c" in command and "good_url" in command:
                # Simulate successful download by creating a dummy file
                cmd_parts = shlex.split(command)
                out_idx = cmd_parts.index("--out") + 1
                dir_idx = cmd_parts.index("--dir") + 1
                file_path = os.path.join(cmd_parts[dir_idx], cmd_parts[out_idx])
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, "w") as f: f.write("dummy content")
                return True, "Mocked aria2c success"
            elif "aria2c" in command and "fail_url" in command:
                return False, "Mocked aria2c failure"
            elif "aria2c" in command and "retry_url" in command:
                # Simulate a case that needs retries
                if not hasattr(self, '_retry_count'): self._retry_count = 0
                self._retry_count +=1
                if self._retry_count < 2: return False, "Mocked aria2c timed out"

                # Simulate successful download after retry
                cmd_parts = shlex.split(command)
                out_idx = cmd_parts.index("--out") + 1
                dir_idx = cmd_parts.index("--dir") + 1
                file_path = os.path.join(cmd_parts[dir_idx], cmd_parts[out_idx])
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, "w") as f: f.write("dummy content for retry_url")
                self._retry_count = 0 # reset for next potential retry_url
                return True, "Mocked aria2c success after retry"

            return False, "Command not specifically mocked"


        def get_random_user_agent(self) -> str:
            return "MockedUserAgent/1.0"

    class MockConfig:
        TEMP_DIR = "temp_downloads"
        OUTPUT_DIR = "output_files"
        DOWNLOADED_URLS_LOG = "logs/downloaded_urls.log"
        FAILED_URLS_LOG = "logs/failed_urls.log"
        ARIA2C_LOG = "logs/aria2c.log"
        MAX_CONCURRENT_DOWNLOADS = "5" # Should be string for aria2c option if directly used
        RETRY_ATTEMPTS = 3
        IP_ROTATION_THRESHOLD_FAILURES = 2
        RETRY_DELAY_SECONDS = 1

    class MockIPRotator:
        async def rotate_wireguard_ip(self) -> bool:
            logging.info("MockIPRotator: Simulating IP rotation.")
            # Simulate success, can be changed to test failure
            return True

    class MockTextConverter:
        async def convert_to_minimized_txt(self, file_path: str, output_path: str) -> bool:
            logging.info(f"MockTextConverter: Simulating text conversion for {file_path} to {output_path}")
            # Simulate successful conversion by creating a dummy output file
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            if "non_selectable.pdf" in file_path or "convert_fail" in file_path : # Simulate PDF discard or conversion failure
                 logging.warning(f"MockTextConverter: Simulating conversion failure/discard for {file_path}")
                 return False
            with open(output_path, "w") as f: f.write("minimized dummy content")
            return True

    utils = MockUtils()
    config = MockConfig()
    ip_rotator = MockIPRotator()
    text_converter = MockTextConverter()

    # Ensure mock log directories exist
    os.makedirs("logs", exist_ok=True)
    os.makedirs(config.TEMP_DIR, exist_ok=True)
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

downloaded_urls_set: Set[str] = set()

async def _load_downloaded_urls():
    """Load already downloaded URLs from the log file."""
    global downloaded_urls_set
    content = await utils.read_file_async(config.DOWNLOADED_URLS_LOG)
    if content:
        downloaded_urls_set = set(line.strip() for line in content.splitlines() if line.strip())
    logging.info(f"Loaded {len(downloaded_urls_set)} URLs from {config.DOWNLOADED_URLS_LOG}")

# Call at module load time or explicitly in an init function if preferred
# For simplicity here, we'll rely on it being called before the main function if this were a script.
# If this module is imported, this should ideally be part of an async setup function.
# asyncio.create_task(_load_downloaded_urls()) # This would run it if event loop is already running

async def download_file_with_aria2c(url: str, target_sub_dir: str) -> bool:
    """
    Downloads a file using aria2c, with retries, IP rotation, and post-conversion.
    """
    global downloaded_urls_set
    # Ensure the set is loaded. This is a simple way for now.
    # A more robust solution might involve a dedicated initialization function for the module/application.
    if not downloaded_urls_set and os.path.exists(config.DOWNLOADED_URLS_LOG): # Avoid re-reading if already populated
        await _load_downloaded_urls()


    if url in downloaded_urls_set:
        logging.info(f"URL already downloaded and processed: {url}. Skipping.")
        return True

    failure_counter = 0

    # Derive file name from URL. Needs to be sanitized if used directly in paths.
    # For aria2c's --out, it handles many characters, but let's get a basic name.
    try:
        file_name_from_url = url.split('/')[-1]
        if not file_name_from_url or len(file_name_from_url) > 200: # Basic sanitization/validation
            file_name_from_url = "downloaded_file" # Fallback
        # Further sanitization might be needed depending on how file_name_from_url is used.
    except Exception:
        file_name_from_url = "downloaded_file"

    # Ensure TEMP_DIR and OUTPUT_DIR subdirectories exist
    # Using os.makedirs for sync operation as it's a pre-requisite.
    # For truly async, use aiofiles.os.makedirs if available or run_in_executor.
    temp_download_dir = os.path.join(config.TEMP_DIR)
    os.makedirs(temp_download_dir, exist_ok=True)

    final_output_dir = os.path.join(config.OUTPUT_DIR, target_sub_dir)
    os.makedirs(final_output_dir, exist_ok=True)

    # Temporary path for aria2c download
    temp_file_path = os.path.join(temp_download_dir, file_name_from_url)
    # Final path for the converted .txt file
    final_txt_output_path = os.path.join(final_output_dir, file_name_from_url + ".txt")


    aria2c_base_command = [
        "aria2c",
        url,
        "--dir", temp_download_dir,
        "--out", file_name_from_url,
        "--user-agent", utils.get_random_user_agent(),
        "--max-connection-per-server", str(config.MAX_CONCURRENT_DOWNLOADS), # Use -x or -s
        "--log", config.ARIA2C_LOG,
        "--allow-overwrite=false", # To prevent overwriting, works with --continue
        "--continue=true",
        "--auto-file-renaming=false", # Important to know the exact output filename
        "--no-file-allocation-limit", # No preallocation
        "--check-certificate=false", # Be cautious with this in production
        "--quiet=true", # Simplify stdout parsing
        "--max-tries=1", # We handle retries in Python
        # Other options like --max-overall-download-limit, --max-download-limit can be added from config
    ]
    # Remove existing log file for aria2c for this specific download attempt to avoid confusion
    # Or use --log-level=warn and parse structured output if available.
    # For simplicity, if ARIA2C_LOG is per download, it's fine. If global, this is problematic.
    # Assuming ARIA2C_LOG is a general log, not per-download unique.

    logging.info(f"Attempting to download URL: {url} to {temp_file_path}")

    for attempt in range(config.RETRY_ATTEMPTS):
        logging.info(f"Download attempt {attempt + 1}/{config.RETRY_ATTEMPTS} for {url}")

        # Construct the command for this attempt (e.g. if user agent needs to be fresh per try)
        # For now, base command is static per call to download_file_with_aria2c
        cmd_str = shlex.join(aria2c_base_command)

        success, output = await utils.run_command(cmd_str)

        if success:
            logging.info(f"Successfully downloaded {url} to {temp_file_path} (raw file).")

            # Post-Download Conversion
            logging.info(f"Starting conversion for {temp_file_path} to {final_txt_output_path}...")
            conversion_success = await text_converter.convert_to_minimized_txt(temp_file_path, final_txt_output_path)

            if conversion_success:
                logging.info(f"Successfully converted {temp_file_path} to {final_txt_output_path}.")
                if await utils.append_to_file_async(config.DOWNLOADED_URLS_LOG, url):
                    downloaded_urls_set.add(url) # Update in-memory set
                else:
                    logging.error(f"Failed to append {url} to {config.DOWNLOADED_URLS_LOG}")

                try:
                    # Use aiofiles for async remove if available and utils wraps it, else sync os.remove
                    # For this example, assuming utils.remove_file_async or similar exists or using os.remove
                    os.remove(temp_file_path)
                    logging.info(f"Deleted temporary file: {temp_file_path}")
                except OSError as e:
                    logging.error(f"Error deleting temporary file {temp_file_path}: {e}")
                return True
            else:
                logging.warning(f"Conversion failed or file discarded for {temp_file_path}.")
                await utils.append_to_file_async(config.FAILED_URLS_LOG, url)
                try:
                    os.remove(temp_file_path)
                    logging.info(f"Deleted temporary file after failed conversion: {temp_file_path}")
                except OSError as e:
                    logging.error(f"Error deleting temporary file {temp_file_path} after failed conversion: {e}")
                return False # Conversion failed

        # Download failed, process retry logic
        logging.warning(f"Download attempt {attempt + 1} failed for {url}. Output: {output}")
        failure_counter += 1

        # Check for specific error messages if needed (e.g. from output string)
        # Example: if "403 Forbidden" in output or "429 Too Many Requests" in output:
        # Perform specific actions. For now, generic retry.

        if failure_counter >= config.IP_ROTATION_THRESHOLD_FAILURES:
            logging.info(f"Failure threshold reached ({failure_counter} failures). Attempting IP rotation.")
            rotation_success = await ip_rotator.rotate_wireguard_ip()
            if rotation_success:
                logging.info("IP rotation successful. Resetting failure counter.")
                failure_counter = 0  # Reset counter after successful rotation
            else:
                logging.warning("IP rotation failed. Continuing with current IP or next retry.")
                # Depending on policy, one might choose to break here or wait longer.

        if attempt < config.RETRY_ATTEMPTS - 1: # If not the last attempt
            logging.info(f"Waiting {config.RETRY_DELAY_SECONDS} seconds before next attempt...")
            await asyncio.sleep(config.RETRY_DELAY_SECONDS)
        else: # Last attempt failed
            logging.error(f"All {config.RETRY_ATTEMPTS} download attempts failed for {url}.")
            await utils.append_to_file_async(config.FAILED_URLS_LOG, url) # Log to failed after all retries
            return False

    return False # Should be unreachable if loop completes, but as a fallback.


if __name__ == '__main__':
    # This example usage demonstrates the flow.
    # Ensure that the mock objects simulate the scenarios you want to test.
    async def test_downloader():
        # Setup: Ensure log files exist for append operations by mocks or real utils
        if not os.path.exists(config.DOWNLOADED_URLS_LOG):
            open(config.DOWNLOADED_URLS_LOG, 'w').close()
        if not os.path.exists(config.FAILED_URLS_LOG):
            open(config.FAILED_URLS_LOG, 'w').close()

        await _load_downloaded_urls() # Load any existing URLs first

        logging.info("\n--- Test Case 1: Successful Download & Conversion ---")
        # `good_url` is set up in MockUtils to succeed aria2c and create a dummy file
        # MockTextConverter is set up to succeed conversion for general cases
        success1 = await download_file_with_aria2c("http://example.com/good_url/document.pdf", "test_docs")
        print(f"Test Case 1 Result: {'Success' if success1 else 'Failure'}\n")

        logging.info("\n--- Test Case 2: URL Already Downloaded ---")
        # This will use the URL from Test Case 1, which should now be in downloaded_urls_set
        success2 = await download_file_with_aria2c("http://example.com/good_url/document.pdf", "test_docs")
        print(f"Test Case 2 Result (should be True as already downloaded): {'Success' if success2 else 'Failure'}\n")

        logging.info("\n--- Test Case 3: Download Fails (e.g., 403 error, simulated by mock) ---")
        # `fail_url` is set up in MockUtils to fail aria2c immediately
        success3 = await download_file_with_aria2c("http://example.com/fail_url/secret.doc", "secret_docs")
        print(f"Test Case 3 Result: {'Success' if success3 else 'Failure'}\n")

        logging.info("\n--- Test Case 4: Download Needs Retries & IP Rotation ---")
        # `retry_url` in MockUtils is set to fail first, then succeed (simulating recovery)
        # MockIPRotator is set to succeed rotation
        # MockConfig.IP_ROTATION_THRESHOLD_FAILURES = 1 (or 2 for the mock to trigger rotation)
        # We set it to 2 in mock, and retry_url fails once then succeeds. So threshold might not be hit depending on exact mock logic.
        # Let's adjust mock config for this test or ensure retry_url fails enough times
        original_threshold = config.IP_ROTATION_THRESHOLD_FAILURES
        config.IP_ROTATION_THRESHOLD_FAILURES = 1 # Force rotation on first failure for this test
        if hasattr(utils, '_retry_count'): utils._retry_count = 0 # Reset mock state
        success4 = await download_file_with_aria2c("http://example.com/retry_url/data.pdf", "data_sets")
        print(f"Test Case 4 Result: {'Success' if success4 else 'Failure'}\n")
        config.IP_ROTATION_THRESHOLD_FAILURES = original_threshold # Reset to original

        logging.info("\n--- Test Case 5: Download Succeeds, but Conversion Fails (e.g., non-selectable PDF) ---")
        # Need a URL that downloads successfully but causes convert_to_minimized_txt to return False
        # We use "convert_fail" in the URL, which MockTextConverter will pick up.
        # MockUtils.run_command will treat this as a "good_url" if not specifically handled, let's ensure it's like good_url
        # For this, we'll make it behave like good_url for download part.
        # The easiest is to make the filename hint to the converter.
        success5 = await download_file_with_aria2c("http://example.com/good_url/non_selectable.pdf", "discarded_docs")
        print(f"Test Case 5 Result (should be False due to conversion fail): {'Success' if success5 else 'Failure'}\n")

        logging.info("\n--- Test Case 6: Download Succeeds, but conversion results in empty file (still success) ---")
        # This scenario is not explicitly different unless convert_to_minimized_txt returns a special signal
        # or if "empty content" is treated as a failure by some other logic.
        # Current text_converter writes empty file and returns True. download_manager will treat this as success.
        # We can simulate this by having a file that results in empty text after normalization.
        # For now, this is covered by Test Case 1's general success.

        # Cleanup dummy files/directories created by mocks if necessary
        # shutil.rmtree(config.TEMP_DIR, ignore_errors=True)
        # shutil.rmtree(config.OUTPUT_DIR, ignore_errors=True)
        # shutil.rmtree("logs", ignore_errors=True)
        # print("Cleaned up mock directories and logs.")

    if __name__ == '__main__':
        # Ensure the event loop is managed correctly if this script is run directly.
        # Python 3.7+
        asyncio.run(test_downloader())
