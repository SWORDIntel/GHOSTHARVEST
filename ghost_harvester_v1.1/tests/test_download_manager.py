import asyncio
import os
import logging
import unittest
from unittest.mock import patch, AsyncMock, MagicMock, call, ANY # Added ANY for some assertions

# Module to be tested
from src import download_manager

# Define a default mock config that can be overridden in tests
DEFAULT_MOCK_CONFIG_VALUES = {
    "TEMP_DIR": "/tmp/gh_temp",
    "OUTPUT_DIR": "/tmp/gh_output",
    "DOWNLOADED_URLS_LOG": "/tmp/gh_logs/downloaded.log",
    "FAILED_URLS_LOG": "/tmp/gh_logs/failed.log",
    "ARIA2C_LOG": "/tmp/gh_logs/aria2c.log",
    "MAX_CONCURRENT_DOWNLOADS": "2", # Note: This is string in download_manager aria2c cmd
    "RETRY_ATTEMPTS": 2,
    "IP_ROTATION_THRESHOLD_FAILURES": 1, # Trigger rotation on first failure for some tests
    "RETRY_DELAY_SECONDS": 0.01 # Speed up tests
}

class TestDownloadManager(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        # Suppress logging
        logging.disable(logging.CRITICAL)

        # Create a new MagicMock for config for each test to isolate config changes
        self.mock_config = MagicMock()
        for key, value in DEFAULT_MOCK_CONFIG_VALUES.items():
            setattr(self.mock_config, key, value)

        # Patch all external dependencies of download_manager
        self.patchers = {
            'utils': patch('src.download_manager.utils', new_callable=MagicMock),
            'ip_rotator': patch('src.download_manager.ip_rotator', new_callable=MagicMock),
            'text_converter': patch('src.download_manager.text_converter', new_callable=MagicMock),
            'config_module': patch('src.download_manager.config', self.mock_config), # Use the instance
            'os_path_exists': patch('src.download_manager.os.path.exists', return_value=True), # Assume files "exist" unless specified
            'os_makedirs': patch('src.download_manager.os.makedirs'),
            'os_remove': patch('src.download_manager.os.remove'),
            'asyncio_sleep': patch('src.download_manager.asyncio.sleep', new_callable=AsyncMock), # For retry delays
            'shlex_join': patch('src.download_manager.shlex.join', side_effect=lambda x: " ".join(x)) # Simple mock for shlex.join
        }

        self.mocks = {name: patcher.start() for name, patcher in self.patchers.items()}

        # Configure specific async mocks or return values for utils
        self.mocks['utils'].run_command = AsyncMock()
        self.mocks['utils'].read_file_async = AsyncMock(return_value=None) # Default: no pre-existing downloaded URLs
        self.mocks['utils'].append_to_file_async = AsyncMock(return_value=True)
        self.mocks['utils'].get_random_user_agent = MagicMock(return_value="TestUserAgent/1.0")

        # Configure specific async mocks for ip_rotator and text_converter
        self.mocks['ip_rotator'].rotate_wireguard_ip = AsyncMock(return_value=True) # Default: rotation succeeds
        self.mocks['text_converter'].convert_to_minimized_txt = AsyncMock(return_value=True) # Default: conversion succeeds

        # Reset download_manager's global downloaded_urls_set before each test by controlling read_file_async
        # The load happens inside download_file_with_aria2c if set is empty.
        download_manager.downloaded_urls_set = set()


    async def asyncTearDown(self):
        logging.disable(logging.NOTSET)
        for patcher in self.patchers.values():
            patcher.stop()

    # --- Test Scenarios for download_file_with_aria2c ---

    async def test_successful_download_and_conversion(self):
        self.mocks['utils'].run_command.return_value = (True, "Download successful")
        test_url = "http://example.com/file.zip"
        target_sub_dir = "test_target"

        # Simulate that the downloaded file will exist for text_converter and subsequent removal
        # The actual temp file path is constructed inside the function.
        # We need to ensure os.path.exists for the temp file returns true after download mock
        # and before os.remove is called. The default mock for os.path.exists is True.

        result = await download_manager.download_file_with_aria2c(test_url, target_sub_dir)

        self.assertTrue(result)
        self.mocks['utils'].run_command.assert_called_once() # Check if aria2c was called
        # Verify aria2c command construction details (optional, but good)
        aria2c_call_args = self.mocks['utils'].run_command.call_args[0][0]
        self.assertIn(test_url, aria2c_call_args)
        self.assertIn(f"--dir {self.mock_config.TEMP_DIR}", aria2c_call_args)
        self.assertIn(f"--out {test_url.split('/')[-1]}", aria2c_call_args)

        self.mocks['text_converter'].convert_to_minimized_txt.assert_called_once()
        # Path for conversion: os.path.join(config.TEMP_DIR, file_name_from_url)
        # Path for output: os.path.join(config.OUTPUT_DIR, target_sub_dir, file_name_from_url + ".txt")
        temp_file_path = os.path.join(self.mock_config.TEMP_DIR, test_url.split('/')[-1])
        final_txt_path = os.path.join(self.mock_config.OUTPUT_DIR, target_sub_dir, test_url.split('/')[-1] + ".txt")
        self.mocks['text_converter'].convert_to_minimized_txt.assert_called_with(temp_file_path, final_txt_path)

        self.mocks['utils'].append_to_file_async.assert_called_once_with(self.mock_config.DOWNLOADED_URLS_LOG, test_url)
        self.mocks['os_remove'].assert_called_once_with(temp_file_path) # Check temp file deletion
        self.assertIn(test_url, download_manager.downloaded_urls_set) # Check in-memory set update


    async def test_url_already_downloaded(self):
        test_url = "http://example.com/already_done.zip"
        # Simulate URL already in log by mocking read_file_async for the _load_downloaded_urls call
        self.mocks['utils'].read_file_async.return_value = test_url + "\n"
        # Force reload or ensure the set is pre-populated based on module's logic
        # Calling _load_downloaded_urls directly or ensuring the main function reloads it.
        # The current download_manager loads it if the global set is empty.
        download_manager.downloaded_urls_set = set() # Ensure it tries to load

        result = await download_manager.download_file_with_aria2c(test_url, "test_target")

        self.assertTrue(result)
        self.mocks['utils'].run_command.assert_not_called()
        self.mocks['text_converter'].convert_to_minimized_txt.assert_not_called()
        self.mocks['utils'].append_to_file_async.assert_not_called() # Not for DOWNLOADED_URLS_LOG again
        # Verify that it logged "URL already downloaded" - requires logging mock configuration
        # For now, checking behavior is primary.


    async def test_download_failure_all_retries_exhausted(self):
        self.mock_config.RETRY_ATTEMPTS = 3
        self.mocks['utils'].run_command.return_value = (False, "Download error 404")
        test_url = "http://example.com/notfound.zip"

        result = await download_manager.download_file_with_aria2c(test_url, "test_target")

        self.assertFalse(result)
        self.assertEqual(self.mocks['utils'].run_command.call_count, self.mock_config.RETRY_ATTEMPTS)
        self.mocks['utils'].append_to_file_async.assert_called_once_with(self.mock_config.FAILED_URLS_LOG, test_url)
        self.mocks['ip_rotator'].rotate_wireguard_ip.assert_not_called() # Assuming threshold not met by default for 3 retries if threshold is e.g. 2 and fails 3 times.
                                                                        # Default IP_ROTATION_THRESHOLD_FAILURES is 1 for tests, so it should be called. Let's adjust.
        self.mock_config.IP_ROTATION_THRESHOLD_FAILURES = 10 # Make sure it's not hit
        # Re-run with this config for this specific assertion
        self.mocks['utils'].run_command.reset_mock()
        self.mocks['utils'].append_to_file_async.reset_mock()
        self.mocks['ip_rotator'].rotate_wireguard_ip.reset_mock()

        result_no_rotation = await download_manager.download_file_with_aria2c(test_url, "test_target")
        self.assertFalse(result_no_rotation)
        self.assertEqual(self.mocks['utils'].run_command.call_count, self.mock_config.RETRY_ATTEMPTS)
        self.mocks['ip_rotator'].rotate_wireguard_ip.assert_not_called()


    async def test_download_failure_with_ip_rotation_trigger(self):
        self.mock_config.RETRY_ATTEMPTS = 3
        self.mock_config.IP_ROTATION_THRESHOLD_FAILURES = 2 # Rotate after 2 failures
        self.mocks['utils'].run_command.return_value = (False, "Download error 403 Forbidden")
        self.mocks['ip_rotator'].rotate_wireguard_ip.return_value = True # Rotation succeeds
        test_url = "http://example.com/forbidden.zip"

        result = await download_manager.download_file_with_aria2c(test_url, "test_target")

        self.assertFalse(result) # Still fails after all retries
        # run_command called RETRY_ATTEMPTS times.
        # IP rotation called once: after 2nd failure, before 3rd attempt.
        # Total run_command calls = 3.
        # Rotation happens on failure_counter = 2. So after 2nd failure, before 3rd attempt.
        self.assertEqual(self.mocks['utils'].run_command.call_count, self.mock_config.RETRY_ATTEMPTS)
        self.mocks['ip_rotator'].rotate_wireguard_ip.assert_called_once()
        # Check failure counter reset: This is internal. We infer by rotation calls.
        # If it wasn't reset, and threshold was 2, it might try to rotate again after 4th virtual failure.
        # Here, only 3 attempts, so one rotation.
        self.mocks['utils'].append_to_file_async.assert_called_once_with(self.mock_config.FAILED_URLS_LOG, test_url)


    async def test_download_success_conversion_fails(self):
        self.mocks['utils'].run_command.return_value = (True, "Download successful")
        self.mocks['text_converter'].convert_to_minimized_txt.return_value = False # Conversion fails
        test_url = "http://example.com/badformat.docx"
        temp_file_path = os.path.join(self.mock_config.TEMP_DIR, test_url.split('/')[-1])

        result = await download_manager.download_file_with_aria2c(test_url, "text_conversion_fail")

        self.assertFalse(result)
        self.mocks['utils'].run_command.assert_called_once()
        self.mocks['text_converter'].convert_to_minimized_txt.assert_called_once()
        self.mocks['utils'].append_to_file_async.assert_called_once_with(self.mock_config.FAILED_URLS_LOG, test_url)
        self.mocks['os_remove'].assert_called_once_with(temp_file_path) # Temp file should still be deleted


    async def test_ip_rotation_fails_during_retries(self):
        self.mock_config.RETRY_ATTEMPTS = 2
        self.mock_config.IP_ROTATION_THRESHOLD_FAILURES = 1 # Rotate on first failure
        self.mocks['utils'].run_command.return_value = (False, "403 Forbidden")
        self.mocks['ip_rotator'].rotate_wireguard_ip.return_value = False # IP Rotation fails
        test_url = "http://example.com/persistent_block.zip"

        result = await download_manager.download_file_with_aria2c(test_url, "test_target")

        self.assertFalse(result)
        # run_command called RETRY_ATTEMPTS times.
        # IP rotation called once after 1st failure. Failure counter NOT reset.
        # Next failure, counter is 2, still >= threshold, but rotation not called again immediately unless logic allows.
        # The current download_manager resets failure_counter only on *successful* rotation.
        # So, if threshold is 1:
        # Attempt 1: DL fail (count=1). Threshold met. Rotate (fails). counter=1. Sleep.
        # Attempt 2: DL fail (count=2). Threshold met. Rotate (fails). counter=2. Sleep.
        # ...
        # So, rotate_wireguard_ip should be called RETRY_ATTEMPTS times if it always fails and threshold is 1.
        self.assertEqual(self.mocks['utils'].run_command.call_count, self.mock_config.RETRY_ATTEMPTS)
        self.assertEqual(self.mocks['ip_rotator'].rotate_wireguard_ip.call_count, self.mock_config.RETRY_ATTEMPTS)
        self.mocks['utils'].append_to_file_async.assert_called_once_with(self.mock_config.FAILED_URLS_LOG, test_url)


    async def test_load_downloaded_urls_state_implicit(self):
        # This tests the internal _load_downloaded_urls via its effect on download_file_with_aria2c
        test_url1 = "http://example.com/file1.txt"
        test_url2 = "http://example.com/file2.txt"
        # Simulate log file having these URLs
        self.mocks['utils'].read_file_async.return_value = f"{test_url1}\n{test_url2}\n"

        # Reset the global set to ensure it loads from the mocked file content
        download_manager.downloaded_urls_set = set()

        # Try to download test_url1 - should be skipped
        result = await download_manager.download_file_with_aria2c(test_url1, "test_target")
        self.assertTrue(result, "Should return True as URL is considered already processed.")
        self.mocks['utils'].run_command.assert_not_called("run_command should not be called for already downloaded URL.")

        # Verify the internal set was populated
        self.assertIn(test_url1, download_manager.downloaded_urls_set)
        self.assertIn(test_url2, download_manager.downloaded_urls_set)

        # Try to download a new URL - should proceed
        new_url = "http://example.com/newfile.txt"
        self.mocks['utils'].run_command.return_value = (True, "Download successful") # Ensure download itself succeeds
        self.mocks['text_converter'].convert_to_minimized_txt.return_value = True # Ensure conversion succeeds

        result_new = await download_manager.download_file_with_aria2c(new_url, "test_target")
        self.assertTrue(result_new, "Download of a new URL should succeed.")
        self.mocks['utils'].run_command.assert_called_once() # Called for the new URL
        self.assertIn(new_url, download_manager.downloaded_urls_set)


if __name__ == '__main__':
    unittest.main()
