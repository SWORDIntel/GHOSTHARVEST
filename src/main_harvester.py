import asyncio
import logging
import random
import signal
import os # For path joining in initialize_system
from typing import Dict, Any, Optional, Set, Coroutine # Added Coroutine for type hint

# Attempt to import actual project modules
try:
    from src import config as app_config # Renamed to avoid conflict with local var if any
    from src import utils
    from src import ip_rotator
    from src import download_manager
    from src import text_converter # Though not directly used, good for import check
    from src.targets import gutenberg # Import module
    from src.targets.base_target import BaseTarget # For type hinting active_target
    from src.interface import cli_interface
except ImportError as e:
    print(f"Critical Import Error: {e}. Some real modules are missing. Using Mocks.")
    # Simplified Mock Objects for main_harvester structure
    class MockModule:
        def __init__(self, name): self.__name__ = name
        def __getattr__(self, item): return lambda *args, **kwargs: logging.warning(f"Mock {self.__name__}.{item} called with {args} {kwargs}") or MockModule(f"{self.__name__}.{item}")
        async def __call__(self, *args, **kwargs): # For async functions
            logging.warning(f"Async Mock {self.__name__} called with {args} {kwargs}")
            if self.__name__.endswith("rotate_wireguard_ip"): return True # Simulate success for initial rotation
            if self.__name__.endswith("get_current_public_ip"): return "127.0.0.1 (mocked)"
            if self.__name__.endswith("init_wireguard_interfaces"): return True
            if self.__name__.endswith("discover_links"): return [] # No links from mock target
            if self.__name__.endswith("get_target_name"): return "mock_target"
            if self.__name__.endswith("download_file_with_aria2c"): return True # Simulate download success
            return None


    app_config = MockModule("config")
    # Make config behave like a dict for get_config/set_config and also allow attribute access
    _mock_config_store = {
        "LOG_DIR": "logs", "LOG_LEVEL": "INFO", "IP_CHECK_SERVICE": "http://ifconfig.me/ip",
        "MAX_CONCURRENT_DOWNLOADS": 2, "DOWNLOADED_URLS_LOG": "logs/main_downloaded.log",
        "MIN_WAIT_BETWEEN_BOOKS_SECONDS": 1, "MAX_WAIT_BETWEEN_BOOKS_SECONDS": 2,
        "RETRY_ATTEMPTS":1, "IP_ROTATION_THRESHOLD_FAILURES":1 # For faster testing
    }
    def mock_get_config(key: str, default: Any = None) -> Any: return _mock_config_store.get(key, default)
    def mock_set_config(key: str, value: Any): _mock_config_store[key] = value
    app_config.get_config = mock_get_config
    app_config.set_config = mock_set_config
    app_config.initialize_directories = lambda: os.makedirs("logs", exist_ok=True)


    utils = MockModule("utils")
    utils.setup_logging = lambda **kwargs: logging.basicConfig(level=kwargs.get('level', logging.INFO), format='%(asctime)s - %(levelname)s - %(message)s')
    utils.read_file_async = lambda path: asyncio.sleep(0.01, result=None) # Simulate async read, returns None
    utils.get_current_public_ip = lambda service_url: asyncio.sleep(0.01, result="127.0.0.1 (mock_utils)")


    ip_rotator = MockModule("ip_rotator")
    download_manager = MockModule("download_manager")
    text_converter = MockModule("text_converter") # Just for import

    # Mock Gutenberg Target
    class MockGutenbergTarget(BaseTarget):
        async def get_target_name(self) -> str: return "mock_gutenberg"
        async def discover_links(self, downloaded_urls: Set[str], keyword_filters: Optional[List[str]] = None) -> List[str]:
            await asyncio.sleep(0.1) # Simulate work
            # Return a few mock links if not in downloaded_urls for testing harvester loop
            mock_links = [f"http://mockgutenberg.org/file{i}.txt" for i in range(5)]
            new_links = [link for link in mock_links if link not in downloaded_urls]
            logging.info(f"MockGutenbergTarget: discovered {len(new_links)} new links.")
            return new_links[:2] # Return only a couple to not overwhelm

    gutenberg = MockModule("gutenberg")
    gutenberg.GutenbergTarget = MockGutenbergTarget

    cli_interface = MockModule("cli_interface")
    # Mock the HarvesterApp and its run method
    class MockHarvesterApp:
        def __init__(self): pass
        def set_queues(self, cmd_q, stat_q): logging.info("MockHarvesterApp: Queues set.")
        def run(self): logging.info("MockHarvesterApp: run() called. Simulating blocking UI.") ; import time; time.sleep(10) # Simulate blocking run
    cli_interface.HarvesterApp = MockHarvesterApp


# --- Global Variables / State ---
command_queue: asyncio.Queue = asyncio.Queue()
status_queue: asyncio.Queue = asyncio.Queue()
harvester_running: asyncio.Event = asyncio.Event()
active_download_tasks: Set[asyncio.Task] = set()
downloaded_urls_in_session: Set[str] = set() # Complements file-based log for current session
current_ip: str = "Initializing..."
active_target: Optional[BaseTarget] = None # Type hint using imported BaseTarget
available_targets: Dict[str, BaseTarget] = {}
stats: Dict[str, int] = {"discovered": 0, "in_progress": 0, "completed": 0, "failed": 0, "discarded": 0} # 'discarded' might be from text_converter via download_manager

# --- Helper Functions ---
async def update_status(msg_type: str, data: Optional[Dict[str, Any]] = None):
    """Puts a message onto status_queue."""
    message = {"type": msg_type}
    if data:
        message.update(data)
    try:
        await status_queue.put(message)
    except Exception as e:
        logging.error(f"Failed to put message on status_queue: {e}")

async def shutdown(loop: asyncio.AbstractEventLoop, signal_event: Optional[asyncio.Event] = None):
    """Handles graceful shutdown."""
    logging.info("Shutdown initiated...")
    if signal_event:
        logging.info(f"Received signal: {signal_event.name}. Cleaning up...")
        signal_event.set() # Signal harvester_loop to stop

    harvester_running.clear() # Stop new tasks from being initiated

    # Cancel all active download tasks
    if active_download_tasks:
        logging.info(f"Cancelling {len(active_download_tasks)} active download tasks...")
        for task in list(active_download_tasks): # Iterate over a copy
            task.cancel()
        # Give tasks a moment to clean up after cancellation
        await asyncio.gather(*active_download_tasks, return_exceptions=True)
        logging.info("All active download tasks cancelled.")

    # Cancel other tasks if needed (e.g. harvester_loop itself if not stopped by signal_event)
    # This depends on how tasks are structured. For now, harvester_loop checks harvester_running.

    # Stop the asyncio loop if it's not already stopping
    # This is generally handled by the top-level asyncio.run() exiting.
    # If loop.stop() is called prematurely, it might interrupt ongoing cleanup.
    # Forcing loop.stop() is usually for more direct loop control, not typical in app shutdown.
    # loop.stop()
    logging.info("Shutdown complete.")


# --- Core Functions ---
async def initialize_system():
    global current_ip, active_target, available_targets, downloaded_urls_in_session

    log_dir = app_config.get_config('LOG_DIR', 'logs')
    log_level_str = app_config.get_config('LOG_LEVEL', 'INFO')
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)

    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)
    log_file_path = os.path.join(log_dir, 'harvester.log')

    # Assuming utils.setup_logging is synchronous or we adapt
    # For now, if it's async, await it. If sync, it needs to be called appropriately.
    # The mock is sync. If real utils.setup_logging is async:
    # await utils.setup_logging(log_file_path=log_file_path, level=log_level)
    # If it's sync:
    utils.setup_logging(log_file_path=log_file_path, level=log_level)
    logging.info("Logging system initialized.")

    # Assuming config.initialize_directories is synchronous
    app_config.initialize_directories()
    logging.info("Application directories initialized.")

    # Load downloaded URLs
    downloaded_log_path = app_config.get_config('DOWNLOADED_URLS_LOG')
    if downloaded_log_path:
        content = await utils.read_file_async(downloaded_log_path)
        if content:
            downloaded_urls_in_session.update(line.strip() for line in content.splitlines() if line.strip())
            logging.info(f"Loaded {len(downloaded_urls_in_session)} previously downloaded URLs.")
            stats["completed"] = len(downloaded_urls_in_session) # Initial stat based on log

    await ip_rotator.init_wireguard_interfaces()
    initial_rotation_success = await ip_rotator.rotate_wireguard_ip()

    if initial_rotation_success:
        # Assuming ip_rotator updates its own current IP state that can be read,
        # or get_current_public_ip is called.
        # current_ip = ip_rotator.current_ip # If available
        current_ip = await utils.get_current_public_ip(app_config.get_config('IP_CHECK_SERVICE'))
        logging.info(f"Initial IP rotation successful. Current IP: {current_ip}")
    else:
        current_ip = "Error: Initial IP Rotation Failed"
        logging.critical("Initial IP rotation failed. Harvester may not function correctly.")
        # Depending on policy, might raise an exception here to stop startup.
    await update_status('ip_update', {'ip': current_ip})

    # Instantiate targets
    gutenberg_target_instance = gutenberg.GutenbergTarget()
    # available_targets needs target name as key
    gt_name = await gutenberg_target_instance.get_target_name()
    available_targets = {gt_name: gutenberg_target_instance}

    active_target = gutenberg_target_instance # Default active target
    active_target_name = await active_target.get_target_name()
    logging.info(f"Active target set to: {active_target_name}")
    await update_status('target_update', {'target_name': active_target_name})

    await update_status('log', {'message': 'System initialized successfully.', 'level': 'INFO'})
    await update_status('stats', stats)


async def harvester_loop(shutdown_event: asyncio.Event):
    global current_ip, active_target, stats # Allow modification of these globals

    logging.info("Harvester loop started.")
    while not shutdown_event.is_set():
        try:
            # --- Command Processing ---
            command_item: Optional[Dict[str, Any]] = None
            try:
                command_item = command_queue.get_nowait()
                command_queue.task_done() # Mark as processed immediately
            except asyncio.QueueEmpty:
                pass # No command, continue

            if command_item:
                command = command_item.get("command")
                logging.debug(f"Processing command: {command}")
                if command == "START":
                    harvester_running.set()
                    await update_status('log', {'message': 'Harvester process started.', 'level': 'INFO'})
                elif command == "STOP":
                    harvester_running.clear()
                    await update_status('log', {'message': 'Harvester process stopped.', 'level': 'INFO'})
                elif command == "ROTATE_IP":
                    await update_status('log', {'message': 'Manual IP rotation requested...', 'level': 'INFO'})
                    rotation_success = await ip_rotator.rotate_wireguard_ip()
                    if rotation_success:
                        current_ip = await utils.get_current_public_ip(app_config.get_config('IP_CHECK_SERVICE')) # Or from ip_rotator state
                        await update_status('ip_update', {'ip': current_ip})
                        await update_status('log', {'message': f'IP rotated successfully. New IP: {current_ip}', 'level': 'INFO'})
                    else:
                        await update_status('log', {'message': 'Manual IP rotation failed.', 'level': 'WARNING'})
                elif command == "SET_CONFIG":
                    settings_to_update = command_item.get("settings", {})
                    for key, value in settings_to_update.items():
                        app_config.set_config(key, value) # Assuming a method in config module
                        logging.info(f"Configuration updated: {key} = {value}")
                    await update_status('log', {'message': f'Settings updated: {settings_to_update}', 'level': 'INFO'})
                elif command == "SET_TARGET":
                    target_name = command_item.get("target_name")
                    if target_name in available_targets:
                        active_target = available_targets[target_name]
                        current_active_target_name = await active_target.get_target_name() # fetch name again
                        await update_status('target_update', {'target_name': current_active_target_name})
                        await update_status('log', {'message': f'Active target switched to: {current_active_target_name}', 'level': 'INFO'})
                    else:
                        await update_status('log', {'message': f'Attempt to switch to unknown target: {target_name}', 'level': 'WARNING'})
                elif command == "EXIT_APP":
                    logging.info("EXIT_APP command received. Shutting down harvester loop.")
                    shutdown_event.set() # Signal loop to stop
                    break # Exit while loop

            # --- Target Discovery & Download Queueing ---
            if harvester_running.is_set() and active_target:
                # Check if we need more tasks
                if len(active_download_tasks) < app_config.get_config('MAX_CONCURRENT_DOWNLOADS', 1):
                    logging.debug(f"Checking for new links. Active tasks: {len(active_download_tasks)}")
                    # Keywords not implemented in this simplified call, pass None or empty list
                    new_links = await active_target.discover_links(downloaded_urls_in_session, keyword_filters=None)

                    for link_url in new_links:
                        if len(active_download_tasks) >= app_config.get_config('MAX_CONCURRENT_DOWNLOADS', 1):
                            logging.debug("Max concurrent downloads reached, deferring new link queueing.")
                            break

                        # Check if URL is already being processed or fully downloaded
                        is_already_processing = any(task.get_name() == link_url for task in active_download_tasks)
                        if link_url not in downloaded_urls_in_session and not is_already_processing:
                            stats['discovered'] += 1
                            target_name_for_download = await active_target.get_target_name()
                            # Create task with a name for easier tracking
                            task = asyncio.create_task(
                                download_manager.download_file_with_aria2c(link_url, target_name_for_download),
                                name=link_url
                            )
                            active_download_tasks.add(task)
                            stats['in_progress'] += 1
                            logging.info(f"Queued download: {link_url} for target {target_name_for_download}. In progress: {stats['in_progress']}")
                            await update_status('stats', stats) # Update stats after queueing one
                        # else:
                            # logging.debug(f"Link {link_url} skipped (already downloaded or processing).")

            # --- Task Management ---
            if active_download_tasks:
                # Use a small timeout to avoid blocking the loop for too long
                done_tasks, pending_tasks = await asyncio.wait(active_download_tasks, timeout=0.1, return_when=asyncio.FIRST_COMPLETED)
                for task in done_tasks:
                    url_processed = task.get_name() # Get URL from task name
                    stats['in_progress'] -= 1
                    try:
                        success = task.result() # True if download + conversion succeeded
                        if success:
                            stats['completed'] += 1
                            downloaded_urls_in_session.add(url_processed) # download_manager already wrote to main log
                            logging.info(f"Download & conversion successful for: {url_processed}. Completed: {stats['completed']}")
                        else:
                            # download_manager logs to FAILED_URLS_LOG and handles if it was a discarded PDF.
                            # Here, we just count it as failed if not successful overall.
                            # TextConverter might discard a PDF and return False; download_manager then returns False.
                            # We need a way to distinguish "discarded" from "genuinely failed".
                            # For now, assume download_manager's False means a failure type for this stat.
                            # A more refined status from download_manager could help (e.g., an enum or specific exception).
                            stats['failed'] += 1
                            logging.warning(f"Processing failed or file discarded for: {url_processed}. Failed count: {stats['failed']}")
                    except asyncio.CancelledError:
                        logging.warning(f"Download task {url_processed} was cancelled.")
                        stats['failed'] +=1 # Or a different category for cancelled
                    except Exception as e:
                        stats['failed'] += 1
                        logging.error(f"Download task for {url_processed} raised an exception: {e}")

                    active_download_tasks.remove(task)
                    await update_status('stats', stats) # Update after each task completion


            # --- Status Updates & Delays ---
            # Periodically update IP (e.g., if ip_rotator has internal state that changes)
            # For now, IP is updated on explicit rotation. If background rotation exists, this would be useful.
            # await update_status('ip_update', {'ip': ip_rotator.current_ip if hasattr(ip_rotator, 'current_ip') else current_ip})

            if harvester_running.is_set() and len(active_download_tasks) > 0:
                # Shorter sleep if actively downloading, just to keep discovery responsive if slots open up
                await asyncio.sleep(0.5)
            elif harvester_running.is_set():
                 # Harvester is running but no tasks, or no new links found, wait before retrying discovery
                min_wait = app_config.get_config('MIN_WAIT_BETWEEN_BOOKS_SECONDS', 1)
                max_wait = app_config.get_config('MAX_WAIT_BETWEEN_BOOKS_SECONDS', 2)
                await asyncio.sleep(random.uniform(min_wait, max_wait))
            else:
                # Harvester is stopped, sleep a bit to keep command processing responsive
                await asyncio.sleep(0.2)

        except asyncio.CancelledError:
            logging.info("Harvester loop cancelled.")
            shutdown_event.set() # Ensure event is set if cancelled externally
            break
        except Exception as e:
            logging.critical(f"Critical error in harvester_loop: {e}", exc_info=True)
            await update_status('log', {'message': f'Critical error in harvester: {e}', 'level': 'CRITICAL'})
            await asyncio.sleep(5) # Avoid rapid looping on persistent error

    logging.info("Harvester loop ended.")


async def start_cli_and_harvester():
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event() # Event to signal harvester_loop to stop

    # Setup signal handlers
    # For SIGINT (Ctrl+C) and SIGTERM (system shutdown)
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(shutdown(loop, shutdown_event)))

    try:
        await initialize_system()

        cli_app = cli_interface.HarvesterApp()
        cli_app.set_queues(command_queue, status_queue)

        harvester_task = asyncio.create_task(harvester_loop(shutdown_event))

        logging.info("Starting CLI application in executor...")
        # npyscreen's app.run() is blocking, so run it in an executor
        cli_future = loop.run_in_executor(None, cli_app.run)

        # Wait for either the harvester or the CLI to complete/raise an exception
        # If CLI exits (e.g. user presses Exit button), cli_future will complete.
        # If harvester_task is cancelled (e.g. by EXIT_APP command), it will complete.
        done, pending = await asyncio.wait(
            [harvester_task, cli_future],
            return_when=asyncio.FIRST_COMPLETED
        )

        for task in done:
            try:
                task.result() # Raise exceptions if any task failed
            except asyncio.CancelledError:
                logging.info(f"Task {task.get_name()} was cancelled.")
            except Exception as e:
                logging.error(f"Task {task.get_name()} failed with exception: {e}", exc_info=True)

        # If one task finishes (e.g. CLI exits), signal others to stop
        shutdown_event.set() # Signal harvester_loop
        for p_task in pending:
            p_task.cancel() # Cancel other pending tasks (e.g., if CLI exited, cancel harvester_task)

        await asyncio.gather(*pending, return_exceptions=True) # Wait for pending tasks to clean up

    except asyncio.CancelledError:
        logging.info("start_cli_and_harvester was cancelled.")
    except Exception as e:
        logging.critical(f"Unhandled exception in start_cli_and_harvester: {e}", exc_info=True)
    finally:
        logging.info("Ensuring final shutdown...")
        # Call shutdown directly to ensure cleanup, especially if loop wasn't stopped by signal
        # This might be redundant if signal handlers worked perfectly but serves as a fallback.
        await shutdown(loop, shutdown_event)


# --- Entry Point ---
if __name__ == '__main__':
    try:
        asyncio.run(start_cli_and_harvester())
    except KeyboardInterrupt:
        logging.info("Harvester shutting down via KeyboardInterrupt (Ctrl+C in main).")
    except Exception as e:
        logging.critical(f"Harvester failed to run due to an unhandled exception in __main__: {e}", exc_info=True)
    finally:
        logging.info("Application has concluded.")
