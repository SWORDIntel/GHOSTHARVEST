import asyncio
import os # Mocked, but imported for context
import logging
import unittest
from unittest.mock import patch, AsyncMock, MagicMock, call, ANY

# Module to be tested (primarily its interaction with text_converter)
from src import download_manager

# Define a default mock config that can be overridden in tests
DEFAULT_MOCK_CONFIG_VALUES = {
    "TEMP_DIR": "/tmp/gh_conv_temp",
    "OUTPUT_DIR": "/tmp/gh_conv_output",
    "DOWNLOADED_URLS_LOG": "/tmp/gh_conv_logs/downloaded.log",
    "FAILED_URLS_LOG": "/tmp/gh_conv_logs/failed.log",
    "ARIA2C_LOG": "/tmp/gh_conv_logs/aria2c.log", # Not directly used in these tests but part of config
    "MAX_CONCURRENT_DOWNLOADS": "1",
    "RETRY_ATTEMPTS": 1, # Simplify tests by default, not focusing on retries here
    "IP_ROTATION_THRESHOLD_FAILURES": 100, # High to avoid rotation interfering
    "RETRY_DELAY_SECONDS": 0.001
}

class TestDownloadManagerTextConversionIntegration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        logging.disable(logging.CRITICAL)

        self.mock_config_instance = MagicMock()
        for key, value in DEFAULT_MOCK_CONFIG_VALUES.items():
            setattr(self.mock_config_instance, key, value)

        self.patchers = {
            'utils': patch('src.download_manager.utils', new_callable=MagicMock),
            'ip_rotator_module': patch('src.download_manager.ip_rotator', new_callable=MagicMock),
            'text_converter_module': patch('src.download_manager.text_converter', new_callable=MagicMock), # Key mock
            'config_module': patch('src.download_manager.config', self.mock_config_instance),
            'os_path_exists': patch('src.download_manager.os.path.exists', return_value=True), # Assume temp file "exists" after mock download
            'os_makedirs': patch('src.download_manager.os.makedirs'),
            'os_remove': patch('src.download_manager.os.remove'),
            'asyncio_sleep': patch('src.download_manager.asyncio.sleep', new_callable=AsyncMock),
        }
        self.mocks = {name: patcher.start() for name, patcher in self.patchers.items()}

        # Configure specific async mocks or return values
        self.mocks['utils'].run_command = AsyncMock() # Configured per test for download success/fail
        self.mocks['utils'].read_file_async = AsyncMock(return_value=None) # No pre-existing downloaded URLs
        self.mocks['utils'].append_to_file_async = AsyncMock(return_value=True)
        self.mocks['utils'].get_random_user_agent = MagicMock(return_value="IntegrationTestUserAgent/Conv/1.0")

        self.mocks['ip_rotator_module'].rotate_wireguard_ip = AsyncMock(return_value=True) # IP rotation not focus here

        # Key mock for this integration test: text_converter.convert_to_minimized_txt
        self.mocks['text_converter_module'].convert_to_minimized_txt = AsyncMock() # Configured per test

        download_manager.downloaded_urls_set = set()

    async def asyncTearDown(self):
        logging.disable(logging.NOTSET)
        for patcher in self.patchers.values():
            patcher.stop()

    # --- Test Scenarios ---

    async def test_successful_download_and_successful_conversion(self):
        test_url = "http://example.com/mydoc.docx"
        file_name = "mydoc.docx"
        target_dir = "word_docs"

        self.mocks['utils'].run_command.return_value = (True, "Download successful") # Simulate aria2c success
        self.mocks['text_converter_module'].convert_to_minimized_txt.return_value = True # Simulate conversion success

        result = await download_manager.download_file_with_aria2c(test_url, target_dir)
        self.assertTrue(result)

        # Verify download call
        self.mocks['utils'].run_command.assert_called_once()
        aria2c_call_args = self.mocks['utils'].run_command.call_args[0][0]
        self.assertIn(test_url, aria2c_call_args)
        self.assertIn(f"--dir {self.mock_config_instance.TEMP_DIR}", aria2c_call_args)
        self.assertIn(f"--out {file_name}", aria2c_call_args)

        # Verify text_converter call
        temp_file_path = os.path.join(self.mock_config_instance.TEMP_DIR, file_name)
        final_output_path = os.path.join(self.mock_config_instance.OUTPUT_DIR, target_dir, file_name + ".txt")
        self.mocks['text_converter_module'].convert_to_minimized_txt.assert_called_once_with(temp_file_path, final_output_path)

        # Verify logging and cleanup
        self.mocks['utils'].append_to_file_async.assert_called_once_with(self.mock_config_instance.DOWNLOADED_URLS_LOG, test_url)
        self.mocks['os_remove'].assert_called_once_with(temp_file_path)
        self.assertIn(test_url, download_manager.downloaded_urls_set)


    async def test_successful_download_conversion_fails(self):
        test_url = "http://example.com/scanned.pdf" # A PDF that converter might reject
        file_name = "scanned.pdf"
        target_dir = "pdfs_failed_conversion"

        self.mocks['utils'].run_command.return_value = (True, "Download successful")
        self.mocks['text_converter_module'].convert_to_minimized_txt.return_value = False # Simulate conversion failure

        result = await download_manager.download_file_with_aria2c(test_url, target_dir)
        self.assertFalse(result)

        self.mocks['utils'].run_command.assert_called_once() # Download still happened

        temp_file_path = os.path.join(self.mock_config_instance.TEMP_DIR, file_name)
        final_output_path = os.path.join(self.mock_config_instance.OUTPUT_DIR, target_dir, file_name + ".txt")
        self.mocks['text_converter_module'].convert_to_minimized_txt.assert_called_once_with(temp_file_path, final_output_path)

        self.mocks['utils'].append_to_file_async.assert_called_once_with(self.mock_config_instance.FAILED_URLS_LOG, test_url)
        self.mocks['os_remove'].assert_called_once_with(temp_file_path) # Temp file still deleted
        self.assertNotIn(test_url, download_manager.downloaded_urls_set) # Not in successful set


    async def test_download_fails_conversion_not_called(self):
        test_url = "http://example.com/brokenlink.txt"
        target_dir = "texts_not_downloaded"
        self.mock_config_instance.RETRY_ATTEMPTS = 1 # Ensure it fails quickly

        self.mocks['utils'].run_command.return_value = (False, "Download error 404") # Simulate aria2c failure

        result = await download_manager.download_file_with_aria2c(test_url, target_dir)
        self.assertFalse(result)

        self.mocks['utils'].run_command.assert_called_once() # Download was attempted
        self.mocks['text_converter_module'].convert_to_minimized_txt.assert_not_called() # Conversion should not be attempted

        self.mocks['utils'].append_to_file_async.assert_called_once_with(self.mock_config_instance.FAILED_URLS_LOG, test_url)
        # os.remove should not be called as no temp file was "created" by the failed download
        self.mocks['os_remove'].assert_not_called()
        self.assertNotIn(test_url, download_manager.downloaded_urls_set)

    async def test_download_file_name_sanitization_if_url_is_weird(self):
        # Test if a weird URL (e.g. ending with / or query params) gets a reasonable filename
        test_url = "http://example.com/getDoc?id=123&type=docx"
        expected_file_name = "downloaded_file" # Default fallback in download_manager
        # Or, if download_manager has more sophisticated sanitization, test that.
        # Current download_manager: url.split('/')[-1] if valid, else "downloaded_file"
        # For "http://example.com/getDoc?id=123&type=docx", split('/')[-1] is "getDoc?id=123&type=docx"
        # Let's assume a more complex case or test the fallback.

        # Case 1: URL that might produce an empty name after split
        test_url_empty_name = "http://example.com/"
        expected_fallback_name = "downloaded_file"
        target_dir = "special_cases"

        self.mocks['utils'].run_command.return_value = (True, "Download successful")
        self.mocks['text_converter_module'].convert_to_minimized_txt.return_value = True

        result = await download_manager.download_file_with_aria2c(test_url_empty_name, target_dir)
        self.assertTrue(result)

        temp_file_path = os.path.join(self.mock_config_instance.TEMP_DIR, expected_fallback_name)
        final_output_path = os.path.join(self.mock_config_instance.OUTPUT_DIR, target_dir, expected_fallback_name + ".txt")

        self.mocks['utils'].run_command.assert_called_once()
        aria2c_call_args_str = self.mocks['utils'].run_command.call_args[0][0]
        self.assertIn(f"--out {expected_fallback_name}", aria2c_call_args_str) # Check if fallback name used in command
        self.mocks['text_converter_module'].convert_to_minimized_txt.assert_called_once_with(temp_file_path, final_output_path)
        self.mocks['os_remove'].assert_called_once_with(temp_file_path)


if __name__ == '__main__':
    unittest.main()
