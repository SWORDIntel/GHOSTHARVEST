import asyncio
import os # Mocked, but imported for context
import logging
import unittest
from unittest.mock import patch, AsyncMock, MagicMock, call, ANY

# Module to be tested (primarily its interaction with ip_rotator)
from src import download_manager

# Define a default mock config that can be overridden in tests
DEFAULT_MOCK_CONFIG_VALUES = {
    "TEMP_DIR": "/tmp/gh_int_temp",
    "OUTPUT_DIR": "/tmp/gh_int_output",
    "DOWNLOADED_URLS_LOG": "/tmp/gh_int_logs/downloaded.log",
    "FAILED_URLS_LOG": "/tmp/gh_int_logs/failed.log",
    "ARIA2C_LOG": "/tmp/gh_int_logs/aria2c.log",
    "MAX_CONCURRENT_DOWNLOADS": "1", # Keep it simple for these tests
    "RETRY_ATTEMPTS": 3,
    "IP_ROTATION_THRESHOLD_FAILURES": 2,
    "RETRY_DELAY_SECONDS": 0.001 # Speed up tests
}

class TestDownloadManagerIPRotationIntegration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        logging.disable(logging.CRITICAL)

        self.mock_config_instance = MagicMock()
        for key, value in DEFAULT_MOCK_CONFIG_VALUES.items():
            setattr(self.mock_config_instance, key, value)

        # Patch all external dependencies of download_manager
        # We are specifically testing the interaction between download_manager and ip_rotator,
        # so ip_rotator itself (the method rotate_wireguard_ip) will be a key mock.
        self.patchers = {
            'utils': patch('src.download_manager.utils', new_callable=MagicMock),
            'text_converter': patch('src.download_manager.text_converter', new_callable=MagicMock),
            'ip_rotator_module': patch('src.download_manager.ip_rotator', new_callable=MagicMock), # Mock the whole module
            'config_module': patch('src.download_manager.config', self.mock_config_instance),
            'os_path_exists': patch('src.download_manager.os.path.exists', return_value=True),
            'os_makedirs': patch('src.download_manager.os.makedirs'),
            'os_remove': patch('src.download_manager.os.remove'),
            'asyncio_sleep': patch('src.download_manager.asyncio.sleep', new_callable=AsyncMock),
        }
        self.mocks = {name: patcher.start() for name, patcher in self.patchers.items()}

        # Configure specific async mocks or return values
        self.mocks['utils'].run_command = AsyncMock() # This will be configured per test
        self.mocks['utils'].read_file_async = AsyncMock(return_value=None) # No pre-existing downloaded URLs
        self.mocks['utils'].append_to_file_async = AsyncMock(return_value=True)
        self.mocks['utils'].get_random_user_agent = MagicMock(return_value="IntegrationTestUserAgent/1.0")

        self.mocks['text_converter'].convert_to_minimized_txt = AsyncMock(return_value=True) # Conversion always succeeds

        # Key mock for this integration test: ip_rotator.rotate_wireguard_ip
        # Access it via the mocked module: self.mocks['ip_rotator_module']
        self.mocks['ip_rotator_module'].rotate_wireguard_ip = AsyncMock(return_value=True) # Default: rotation succeeds

        # Reset download_manager's global downloaded_urls_set
        download_manager.downloaded_urls_set = set()

    async def asyncTearDown(self):
        logging.disable(logging.NOTSET)
        for patcher in self.patchers.values():
            patcher.stop()

    # --- Test Scenarios ---

    async def test_ip_rotation_triggered_and_succeeds_download_then_succeeds(self):
        # Config: Rotate after 2 failures, 3 total attempts for download.
        self.mock_config_instance.IP_ROTATION_THRESHOLD_FAILURES = 2
        self.mock_config_instance.RETRY_ATTEMPTS = 3

        # run_command: Fail twice, then succeed on the third attempt (after rotation)
        self.mocks['utils'].run_command.side_effect = [
            (False, "403 Forbidden"),
            (False, "403 Forbidden"),
            (True, "Download successful")
        ]
        self.mocks['ip_rotator_module'].rotate_wireguard_ip.return_value = True # IP Rotation succeeds

        test_url = "http://example.com/file_needs_rotation.zip"
        result = await download_manager.download_file_with_aria2c(test_url, "target1")

        self.assertTrue(result, "Download should eventually succeed after rotation.")

        # Check calls to run_command (aria2c)
        self.assertEqual(self.mocks['utils'].run_command.call_count, 3, "aria2c should be called 3 times (fail, fail, success).")

        # Check call to ip_rotator.rotate_wireguard_ip
        self.mocks['ip_rotator_module'].rotate_wireguard_ip.assert_called_once() # Called after 2nd failure

        # Check that the URL was logged as successful
        self.mocks['utils'].append_to_file_async.assert_called_with(self.mock_config_instance.DOWNLOADED_URLS_LOG, test_url)


    async def test_ip_rotation_not_triggered_failures_less_than_threshold(self):
        self.mock_config_instance.IP_ROTATION_THRESHOLD_FAILURES = 3
        self.mock_config_instance.RETRY_ATTEMPTS = 2 # Only 2 attempts, less than threshold

        self.mocks['utils'].run_command.return_value = (False, "403 Forbidden") # Always fails

        test_url = "http://example.com/file_no_rotation_needed.zip"
        result = await download_manager.download_file_with_aria2c(test_url, "target2")

        self.assertFalse(result, "Download should fail as all retries are exhausted.")
        self.assertEqual(self.mocks['utils'].run_command.call_count, 2, "aria2c should be called RETRY_ATTEMPTS (2) times.")
        self.mocks['ip_rotator_module'].rotate_wireguard_ip.assert_not_called() # Rotation should not be triggered
        self.mocks['utils'].append_to_file_async.assert_called_with(self.mock_config_instance.FAILED_URLS_LOG, test_url)


    async def test_ip_rotation_triggered_but_rotation_itself_fails(self):
        self.mock_config_instance.IP_ROTATION_THRESHOLD_FAILURES = 1 # Rotate on 1st failure
        self.mock_config_instance.RETRY_ATTEMPTS = 3

        self.mocks['utils'].run_command.return_value = (False, "403 Forbidden") # Download always fails
        self.mocks['ip_rotator_module'].rotate_wireguard_ip.return_value = False # IP Rotation fails

        test_url = "http://example.com/file_rotation_fails.zip"
        result = await download_manager.download_file_with_aria2c(test_url, "target3")

        self.assertFalse(result, "Download should ultimately fail.")
        self.assertEqual(self.mocks['utils'].run_command.call_count, 3, "aria2c should be called RETRY_ATTEMPTS (3) times.")

        # Rotation is attempted after each failure if threshold is 1 and rotation keeps failing (failure counter not reset)
        # Attempt 1: run_command fails. failure_counter = 1. Threshold met. rotate_ip (fails).
        # Attempt 2: run_command fails. failure_counter = 2. Threshold met. rotate_ip (fails).
        # Attempt 3: run_command fails. failure_counter = 3. Threshold met. rotate_ip (fails).
        self.assertEqual(self.mocks['ip_rotator_module'].rotate_wireguard_ip.call_count, 3)
        self.mocks['utils'].append_to_file_async.assert_called_with(self.mock_config_instance.FAILED_URLS_LOG, test_url)


    async def test_multiple_successful_rotations_if_failures_persist(self):
        self.mock_config_instance.IP_ROTATION_THRESHOLD_FAILURES = 1 # Rotate on each failure
        self.mock_config_instance.RETRY_ATTEMPTS = 4

        self.mocks['utils'].run_command.return_value = (False, "403 Forbidden") # Download always fails
        self.mocks['ip_rotator_module'].rotate_wireguard_ip.return_value = True # IP Rotation always SUCCEEDS

        test_url = "http://example.com/file_multiple_rotations.zip"
        result = await download_manager.download_file_with_aria2c(test_url, "target4")

        self.assertFalse(result, "Download should ultimately fail if run_command always fails.")
        self.assertEqual(self.mocks['utils'].run_command.call_count, 4, "aria2c should be called RETRY_ATTEMPTS (4) times.")

        # If rotation threshold is 1 and rotation SUCCEEDS, failure_counter is reset.
        # Attempt 1: run_command fails. failure_counter = 1. Threshold met. rotate_ip (succeeds). failure_counter = 0.
        # Attempt 2: run_command fails. failure_counter = 1. Threshold met. rotate_ip (succeeds). failure_counter = 0.
        # Attempt 3: run_command fails. failure_counter = 1. Threshold met. rotate_ip (succeeds). failure_counter = 0.
        # Attempt 4: run_command fails. failure_counter = 1. (No more retries, so no more rotation call)
        # So, rotate_wireguard_ip should be called 3 times.
        self.assertEqual(self.mocks['ip_rotator_module'].rotate_wireguard_ip.call_count, 3)
        self.mocks['utils'].append_to_file_async.assert_called_with(self.mock_config_instance.FAILED_URLS_LOG, test_url)

    async def test_download_succeeds_before_rotation_threshold(self):
        self.mock_config_instance.IP_ROTATION_THRESHOLD_FAILURES = 2
        self.mock_config_instance.RETRY_ATTEMPTS = 3

        # run_command: Fail once, then succeed.
        self.mocks['utils'].run_command.side_effect = [
            (False, "Temporary glitch"),
            (True, "Download successful")
        ]

        test_url = "http://example.com/file_success_before_threshold.zip"
        result = await download_manager.download_file_with_aria2c(test_url, "target5")

        self.assertTrue(result, "Download should succeed.")
        self.assertEqual(self.mocks['utils'].run_command.call_count, 2, "aria2c should be called twice (fail, success).")
        self.mocks['ip_rotator_module'].rotate_wireguard_ip.assert_not_called() # Rotation threshold not met
        self.mocks['utils'].append_to_file_async.assert_called_with(self.mock_config_instance.DOWNLOADED_URLS_LOG, test_url)


if __name__ == '__main__':
    unittest.main()
