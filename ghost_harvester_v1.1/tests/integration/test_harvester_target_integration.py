import asyncio
import logging
import unittest
from unittest.mock import patch, AsyncMock, MagicMock, call, ANY

# Modules to be tested or involved
from src import main_harvester
# We will be patching modules as they are imported by main_harvester

# Define a default mock config that can be overridden in tests
DEFAULT_MOCK_CONFIG_VALUES = {
    "LOG_DIR": "/tmp/gh_target_int_logs",
    "LOG_LEVEL": "DEBUG",
    "DOWNLOADED_URLS_LOG": "/tmp/gh_target_int_logs/downloaded.log",
    "IP_CHECK_SERVICE": "http://ifconfig.me/ip", # From main_harvester's initialize_system
    "MAX_CONCURRENT_DOWNLOADS": 2,
    "MIN_WAIT_BETWEEN_BOOKS_SECONDS": 0.001, # Speed up tests
    "MAX_WAIT_BETWEEN_BOOKS_SECONDS": 0.002,
    # Add other config values main_harvester.initialize_system might need
}

class TestHarvesterTargetIntegration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        logging.disable(logging.CRITICAL)

        self.mock_config_instance = MagicMock()
        # Configure get_config method on the mock config instance
        def get_config_side_effect(key, default=None):
            return getattr(self.mock_config_instance, key, default) # Get attr if exists

        self.mock_config_instance.get_config = MagicMock(side_effect=get_config_side_effect)

        for key, value in DEFAULT_MOCK_CONFIG_VALUES.items():
            setattr(self.mock_config_instance, key, value) # Set directly for direct access if any

        # Patch all external dependencies of main_harvester
        self.patchers = {
            'utils': patch('src.main_harvester.utils', new_callable=MagicMock),
            'ip_rotator': patch('src.main_harvester.ip_rotator', new_callable=MagicMock),
            'download_manager': patch('src.main_harvester.download_manager', new_callable=MagicMock),
            'config_module': patch('src.main_harvester.app_config', self.mock_config_instance), # app_config in main_harvester
            'gutenberg_target_class': patch('src.main_harvester.gutenberg.GutenbergTarget', new_callable=MagicMock),
            'cli_interface_app': patch('src.main_harvester.cli_interface.HarvesterApp', new_callable=MagicMock), # For initialize_system via start_cli_and_harvester
            'asyncio_sleep': patch('src.main_harvester.asyncio.sleep', new_callable=AsyncMock),
            'status_queue_put': patch.object(main_harvester.status_queue, 'put', new_callable=AsyncMock),
            'command_queue_get_nowait': patch.object(main_harvester.command_queue, 'get_nowait', new_callable=MagicMock),
        }
        self.mocks = {name: patcher.start() for name, patcher in self.patchers.items()}

        # Configure specific mock behaviors
        self.mocks['utils'].setup_logging = MagicMock()
        self.mocks['utils'].read_file_async = AsyncMock(return_value=None) # No prior downloaded URLs
        self.mocks['utils'].get_current_public_ip = AsyncMock(return_value="127.0.0.1")

        self.mocks['ip_rotator'].init_wireguard_interfaces = AsyncMock()
        self.mocks['ip_rotator'].rotate_wireguard_ip = AsyncMock(return_value=True) # Initial rotation success

        self.mocks['download_manager'].download_file_with_aria2c = AsyncMock(return_value=True) # Download succeeds by default

        # Mock the GutenbergTarget instance that will be created in initialize_system
        self.mock_target_instance = AsyncMock() # This will be our active_target
        self.mock_target_instance.get_target_name = AsyncMock(return_value="mock_gutenberg_target")
        self.mock_target_instance.discover_links = AsyncMock(return_value=[]) # Default: no links
        self.mocks['gutenberg_target_class'].return_value = self.mock_target_instance

        self.mocks['command_queue_get_nowait'].side_effect = asyncio.QueueEmpty # No commands by default

        # Reset main_harvester's global state (as much as possible)
        main_harvester.harvester_running.clear()
        main_harvester.active_download_tasks = set()
        main_harvester.downloaded_urls_in_session = set()
        main_harvester.stats = {"discovered": 0, "in_progress": 0, "completed": 0, "failed": 0, "discarded": 0}
        main_harvester.active_target = None # Will be set by initialize_system
        main_harvester.available_targets = {}

        # Call initialize_system to set up main_harvester state including active_target
        # This is part of the setup for testing harvester_loop
        await main_harvester.initialize_system()
        # Ensure active_target is set to our mock instance
        self.assertEqual(main_harvester.active_target, self.mock_target_instance)


    async def asyncTearDown(self):
        logging.disable(logging.NOTSET)
        for patcher in self.patchers.values():
            patcher.stop()
        # Clear the event in case a test set it and didn't clean up
        main_harvester.harvester_running.clear()

    async def run_harvester_loop_iterations(self, iterations=1):
        """Helper to run the harvester_loop for a few iterations."""
        shutdown_event = asyncio.Event()

        async def stop_loop_after_iterations():
            for _ in range(iterations):
                # Allow one main check cycle of harvester_loop to run
                # The sleep inside harvester_loop is mocked, so this relies on other await points
                # or the loop structure itself to yield control.
                # We can also make the mocked sleep raise an exception after N calls.
                await asyncio.sleep(0.0001) # Minimal sleep to allow loop to cycle
            shutdown_event.set()

        loop_task = asyncio.create_task(main_harvester.harvester_loop(shutdown_event))
        stopper_task = asyncio.create_task(stop_loop_after_iterations())

        await asyncio.wait([loop_task, stopper_task], return_when=asyncio.ALL_COMPLETED)
        # Ensure any exceptions in harvester_loop are raised if needed
        if loop_task.done() and loop_task.exception():
            raise loop_task.exception()


    async def test_discover_and_queue_new_links(self):
        self.mock_config_instance.MAX_CONCURRENT_DOWNLOADS = 2
        main_harvester.harvester_running.set() # Start the harvester

        # Configure mock target to return new links
        discovered_links_list = ["http://example.com/book1.txt", "http://example.com/book2.txt", "http://example.com/book3.txt"]
        self.mock_target_instance.discover_links.return_value = discovered_links_list

        await self.run_harvester_loop_iterations(iterations=2) # Allow a couple of cycles for processing

        self.mock_target_instance.discover_links.assert_called_with(main_harvester.downloaded_urls_in_session, keyword_filters=None)

        # Check download_manager calls - should be limited by MAX_CONCURRENT_DOWNLOADS
        self.assertEqual(self.mocks['download_manager'].download_file_with_aria2c.call_count, 2)
        self.mocks['download_manager'].download_file_with_aria2c.assert_any_call(discovered_links_list[0], "mock_gutenberg_target")
        self.mocks['download_manager'].download_file_with_aria2c.assert_any_call(discovered_links_list[1], "mock_gutenberg_target")
        # The third link should not be called yet due to concurrency limit

        self.assertEqual(len(main_harvester.active_download_tasks), 2)
        task_names = {task.get_name() for task in main_harvester.active_download_tasks}
        self.assertIn(discovered_links_list[0], task_names)
        self.assertIn(discovered_links_list[1], task_names)

        self.assertEqual(main_harvester.stats['discovered'], 3) # All 3 are discovered
        self.assertEqual(main_harvester.stats['in_progress'], 2) # But only 2 queued initially


    async def test_no_new_links_discovered(self):
        self.mock_config_instance.MAX_CONCURRENT_DOWNLOADS = 2
        main_harvester.harvester_running.set()
        self.mock_target_instance.discover_links.return_value = [] # No links

        await self.run_harvester_loop_iterations(iterations=1)

        self.mock_target_instance.discover_links.assert_called_once()
        self.mocks['download_manager'].download_file_with_aria2c.assert_not_called()
        self.assertEqual(len(main_harvester.active_download_tasks), 0)
        self.assertEqual(main_harvester.stats['in_progress'], 0)


    async def test_links_discovered_are_already_in_session_or_active(self):
        self.mock_config_instance.MAX_CONCURRENT_DOWNLOADS = 2
        main_harvester.harvester_running.set()

        url1 = "http://example.com/book1.txt"
        url2 = "http://example.com/book2.txt" # This one will be "active"
        url3 = "http://example.com/book3.txt" # This one will be new

        main_harvester.downloaded_urls_in_session.add(url1)

        # Simulate url2 being an active task (name must match URL)
        mock_active_task = asyncio.create_task(asyncio.sleep(0.01), name=url2) # Dummy task
        main_harvester.active_download_tasks.add(mock_active_task)
        # Ensure stats reflect this pre-existing task if necessary, or reset stats for clarity
        main_harvester.stats['in_progress'] = 1


        self.mock_target_instance.discover_links.return_value = [url1, url2, url3]

        await self.run_harvester_loop_iterations(iterations=2)

        self.mock_target_instance.discover_links.assert_called_with(main_harvester.downloaded_urls_in_session, keyword_filters=None)

        # download_file_with_aria2c should only be called for url3
        self.mocks['download_manager'].download_file_with_aria2c.assert_called_once_with(url3, "mock_gutenberg_target")

        self.assertEqual(len(main_harvester.active_download_tasks), 2) # mock_active_task + new task for url3
        task_names = {task.get_name() for task in main_harvester.active_download_tasks}
        self.assertIn(url2, task_names) # Existing active task
        self.assertIn(url3, task_names) # New task

        # Discovered stat should increment for url3, but not for url1, url2 if already known/active
        # The 'discovered' stat in main_harvester increments when a link from discover_links is new
        # and not already being processed. url1 is in session, url2 is active. So only url3 is "newly discovered" for queueing.
        self.assertEqual(main_harvester.stats['discovered'], 1) # Only url3
        self.assertEqual(main_harvester.stats['in_progress'], 2) # url2 (pre-existing) + url3 (newly queued)

        # Cleanup the manually created task
        if not mock_active_task.done():
            mock_active_task.cancel()
            try:
                await mock_active_task
            except asyncio.CancelledError:
                pass


if __name__ == '__main__':
    unittest.main()
