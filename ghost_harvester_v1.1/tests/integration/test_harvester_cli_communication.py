import asyncio
import logging
import unittest
from unittest.mock import patch, AsyncMock, MagicMock, call, ANY

# Module to be tested (primarily its interaction with queues)
from src import main_harvester

# Default config values that might be accessed by harvester_loop or initialize_system
DEFAULT_MOCK_CONFIG_VALUES = {
    "LOG_DIR": "/tmp/gh_comm_logs",
    "LOG_LEVEL": "DEBUG",
    "DOWNLOADED_URLS_LOG": "/tmp/gh_comm_logs/downloaded.log",
    "IP_CHECK_SERVICE": "http://ifconfig.me/ip",
    "MAX_CONCURRENT_DOWNLOADS": 1, # Keep simple for these tests
    "MIN_WAIT_BETWEEN_BOOKS_SECONDS": 0.001,
    "MAX_WAIT_BETWEEN_BOOKS_SECONDS": 0.002,
    # For SET_CONFIG command test
    "MAX_CONCURRENT_DOWNLOADS_original": 1,
    "MAX_CONCURRENT_DOWNLOADS_new": 10,
}

class TestHarvesterCLICommunication(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        logging.disable(logging.CRITICAL)

        # Use REAL asyncio.Queue instances for testing communication
        self.test_command_queue = asyncio.Queue()
        self.test_status_queue = asyncio.Queue()

        # Patch the module-level queues in main_harvester to use our test instances
        patch.object(main_harvester, 'command_queue', self.test_command_queue).start()
        patch.object(main_harvester, 'status_queue', self.test_status_queue).start()
        self.addCleanup(patch.stopall) # Stops all patchers started with start()

        self.mock_config_instance = MagicMock()
        def get_config_side_effect(key, default=None):
            return getattr(self.mock_config_instance, key, default)
        self.mock_config_instance.get_config = MagicMock(side_effect=get_config_side_effect)
        # Allow set_config to modify attributes on the mock_config_instance for testing SET_CONFIG
        def set_config_side_effect(key, value):
            setattr(self.mock_config_instance, key, value)
            logging.info(f"Mock config set: {key} = {value}") # For test visibility
        self.mock_config_instance.set_config = MagicMock(side_effect=set_config_side_effect)


        for key, value in DEFAULT_MOCK_CONFIG_VALUES.items():
            setattr(self.mock_config_instance, key, value)

        # Patch other dependencies of main_harvester as needed
        self.patchers = {
            'utils': patch('src.main_harvester.utils', new_callable=MagicMock),
            'ip_rotator': patch('src.main_harvester.ip_rotator', new_callable=MagicMock),
            'download_manager': patch('src.main_harvester.download_manager', new_callable=MagicMock),
            'config_module': patch('src.main_harvester.app_config', self.mock_config_instance),
            'gutenberg_target_class': patch('src.main_harvester.gutenberg.GutenbergTarget', new_callable=MagicMock),
            'asyncio_sleep': patch('src.main_harvester.asyncio.sleep', new_callable=AsyncMock),
            # No need to patch queues themselves, as we replaced the instances.
        }
        self.mocks = {name: patcher.start() for name, patcher in self.patchers.items()}
        self.addCleanup(self.stop_all_patchers)


        # Configure default behaviors for critical mocks
        self.mocks['utils'].setup_logging = MagicMock()
        self.mocks['utils'].read_file_async = AsyncMock(return_value=None)
        self.mocks['utils'].get_current_public_ip = AsyncMock(return_value="127.0.0.1 (mock_setup)")

        self.mocks['ip_rotator'].init_wireguard_interfaces = AsyncMock()
        self.mocks['ip_rotator'].rotate_wireguard_ip = AsyncMock(return_value=True) # Rotation itself succeeds

        self.mocks['download_manager'].download_file_with_aria2c = AsyncMock(return_value=True)

        self.mock_target_instance = AsyncMock()
        self.mock_target_instance.get_target_name = AsyncMock(return_value="initial_mock_target")
        self.mock_target_instance.discover_links = AsyncMock(return_value=[])
        self.mocks['gutenberg_target_class'].return_value = self.mock_target_instance

        # Reset main_harvester's state (as initialize_system might be complex to call fully)
        main_harvester.harvester_running.clear()
        main_harvester.active_download_tasks = set()
        main_harvester.downloaded_urls_in_session = set()
        main_harvester.stats = {"discovered": 0, "in_progress": 0, "completed": 0, "failed": 0, "discarded": 0}
        # Simulate a simplified initialization for relevant parts
        main_harvester.current_ip = "127.0.0.1 (setup)"
        main_harvester.active_target = self.mock_target_instance
        main_harvester.available_targets = {"initial_mock_target": self.mock_target_instance}


    def stop_all_patchers(self): # New method for explicitness if needed beyond addCleanup
        for patcher in self.patchers.values():
            patcher.stop()

    async def run_harvester_loop_for_processing(self, num_iterations=1):
        """Run harvester_loop for a short duration to process commands/emit status."""
        shutdown_event = asyncio.Event()

        # Make asyncio.sleep raise an exception after N calls to break the loop
        sleep_call_count = 0
        original_sleep = self.mocks['asyncio_sleep'] # already an AsyncMock

        async def controlled_sleep(*args, **kwargs):
            nonlocal sleep_call_count
            sleep_call_count += 1
            if sleep_call_count > num_iterations:
                # print(f"Controlled sleep: stopping loop after {num_iterations} iterations.")
                shutdown_event.set() # Signal loop to stop
                raise asyncio.CancelledError("Controlled stop by test") # Also force break if needed
            return await original_sleep(*args, **kwargs) # Call original mock if not stopping

        self.mocks['asyncio_sleep'].side_effect = controlled_sleep

        loop_task = asyncio.create_task(main_harvester.harvester_loop(shutdown_event))

        try:
            await asyncio.wait_for(loop_task, timeout=1.0) # Increased timeout slightly
        except asyncio.TimeoutError:
            # This can happen if the loop doesn't hit the sleep condition enough times
            # print("Harvester loop timed out in test runner.")
            shutdown_event.set() # Ensure it's set
            if not loop_task.done(): loop_task.cancel()
        except asyncio.CancelledError:
            # print("Harvester loop cancelled as expected by controlled_sleep.")
            pass # Expected if controlled_sleep raises CancelledError

        # Ensure task is awaited to propagate any other exceptions
        if not loop_task.done():
            loop_task.cancel() # Ensure it's cancelled if not stopped by event/exception
        try:
            await loop_task # Wait for cancellation or completion
        except asyncio.CancelledError:
            pass # Expected

    # --- Test Scenarios for CLI Commands to Harvester ---

    async def test_command_start(self):
        self.assertFalse(main_harvester.harvester_running.is_set())
        await self.test_command_queue.put({'command': 'START'})
        await self.run_harvester_loop_for_processing(num_iterations=2)
        self.assertTrue(main_harvester.harvester_running.is_set())

    async def test_command_stop(self):
        main_harvester.harvester_running.set() # Start it initially
        self.assertTrue(main_harvester.harvester_running.is_set())
        await self.test_command_queue.put({'command': 'STOP'})
        await self.run_harvester_loop_for_processing(num_iterations=2)
        self.assertFalse(main_harvester.harvester_running.is_set())

    async def test_command_rotate_ip(self):
        await self.test_command_queue.put({'command': 'ROTATE_IP'})
        await self.run_harvester_loop_for_processing(num_iterations=2)
        self.mocks['ip_rotator'].rotate_wireguard_ip.assert_called_once()
        # Also check for status update if IP changed
        # This requires rotate_wireguard_ip to signal an IP change, which it does.
        # And get_current_public_ip to provide the new IP.
        self.mocks['utils'].get_current_public_ip.assert_called_once()


    async def test_command_set_config(self):
        new_max_downloads = DEFAULT_MOCK_CONFIG_VALUES['MAX_CONCURRENT_DOWNLOADS_new']
        payload = {'MAX_CONCURRENT_DOWNLOADS': new_max_downloads}
        await self.test_command_queue.put({'command': 'SET_CONFIG', 'settings': payload})
        await self.run_harvester_loop_for_processing(num_iterations=2)
        # Check if the mock_config_instance's set_config was called
        self.mock_config_instance.set_config.assert_called_once_with('MAX_CONCURRENT_DOWNLOADS', new_max_downloads)
        # And that the attribute on the mock_config_instance was updated by the side_effect
        self.assertEqual(self.mock_config_instance.MAX_CONCURRENT_DOWNLOADS, new_max_downloads)


    async def test_command_set_target(self):
        new_target_mock = AsyncMock()
        new_target_name = "new_mock_target"
        new_target_mock.get_target_name = AsyncMock(return_value=new_target_name)
        main_harvester.available_targets[new_target_name] = new_target_mock

        await self.test_command_queue.put({'command': 'SET_TARGET', 'target_name': new_target_name})
        await self.run_harvester_loop_for_processing(num_iterations=2)
        self.assertEqual(main_harvester.active_target, new_target_mock)


    # --- Test Scenarios for Harvester Status to CLI ---

    async def test_status_update_ip_change(self):
        # Trigger IP change via ROTATE_IP command, which should then send status
        new_ip = "100.200.100.200"
        self.mocks['utils'].get_current_public_ip.return_value = new_ip # After rotation

        await self.test_command_queue.put({'command': 'ROTATE_IP'})
        await self.run_harvester_loop_for_processing(num_iterations=2) # Allow command processing & status update

        # Check status queue for IP update
        # The status_queue.put is already patched by self.mocks['status_queue_put']
        # So we check its calls.
        found_ip_update = False
        for call_args in self.mocks['status_queue_put'].call_args_list:
            message = call_args[0][0] # First argument of the call
            if message.get("type") == "ip_update" and message.get("ip") == new_ip:
                found_ip_update = True
                break
        self.assertTrue(found_ip_update, "IP update message not found in status queue")


    async def test_status_update_log_message(self):
        # A command like START/STOP should generate a log status
        await self.test_command_queue.put({'command': 'START'})
        await self.run_harvester_loop_for_processing(num_iterations=2)

        found_log_update = False
        for call_args in self.mocks['status_queue_put'].call_args_list:
            message = call_args[0][0]
            if message.get("type") == "log" and "Harvester process started" in message.get("message", ""):
                found_log_update = True
                break
        self.assertTrue(found_log_update, "Log message for START not found in status queue")


    async def test_status_update_stats_change(self):
        # Simulate a download task completing to trigger stats update
        # This is a bit more involved as it needs the task management part of harvester_loop
        main_harvester.harvester_running.set()
        self.mock_config_instance.MAX_CONCURRENT_DOWNLOADS = 1

        test_url = "http://example.com/statstest.txt"
        self.mock_target_instance.discover_links.return_value = [test_url] # Discover one link
        self.mocks['download_manager'].download_file_with_aria2c.return_value = True # Download succeeds

        # Run loop: iteration 1 discovers & starts task. Iteration 2 should process its completion.
        await self.run_harvester_loop_for_processing(num_iterations=3)

        # Check for stats update
        found_stats_update = False
        final_stats = None
        for call_args in self.mocks['status_queue_put'].call_args_list:
            message = call_args[0][0]
            if message.get("type") == "stats":
                found_stats_update = True
                final_stats = message # capture the last stats message
                # print(f"Found stats update: {message}")

        self.assertTrue(found_stats_update, "Stats update message not found in status queue")
        if final_stats: # Check specific stats if a message was found
            self.assertEqual(final_stats.get("discovered"), 1)
            self.assertEqual(final_stats.get("completed"), 1)
            self.assertEqual(final_stats.get("in_progress"), 0)


    async def test_status_update_target_change(self):
        new_target_mock = AsyncMock()
        new_target_name = "brand_new_target"
        new_target_mock.get_target_name = AsyncMock(return_value=new_target_name)
        main_harvester.available_targets[new_target_name] = new_target_mock

        await self.test_command_queue.put({'command': 'SET_TARGET', 'target_name': new_target_name})
        await self.run_harvester_loop_for_processing(num_iterations=2)

        found_target_update = False
        for call_args in self.mocks['status_queue_put'].call_args_list:
            message = call_args[0][0]
            if message.get("type") == "target_update" and message.get("target_name") == new_target_name:
                found_target_update = True
                break
        self.assertTrue(found_target_update, "Target update message not found in status queue")


if __name__ == '__main__':
    unittest.main()
