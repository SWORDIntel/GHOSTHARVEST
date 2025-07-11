import asyncio
import logging
import random
import signal
import os
import argparse # For path joining in initialize_system
from typing import Dict, Any, Optional, Set, Coroutine, List # Added Coroutine for type hint

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
stats: Dict[str, int] = {"discovered": 0, "in_progress": 0, "completed": 0, "failed": 0, "discarded": 0}
cli_args: Optional[argparse.Namespace] = None # To store parsed CLI arguments globally
keyword_filters_from_cli: Optional[List[str]] = None # Store keywords from CLI

# --- Helper Functions ---
async def update_status(msg_type: str, data: Optional[Dict[str, Any]] = None, is_headless: bool = False):
    """Puts a message onto status_queue if not headless, otherwise logs it."""
    message = {"type": msg_type}
    if data:
        message.update(data)

    if is_headless:
        # In headless mode, log status updates that would go to TUI
        log_level = logging.INFO # Default for status messages
        if msg_type == "log" and data and "level" in data:
            log_level = getattr(logging, data["level"].upper(), logging.INFO)

        log_message_content = data.get('message', str(data)) if data else msg_type

        if msg_type == "ip_update":
            logging.log(log_level, f"Status Update (IP): {data.get('ip', 'N/A')}")
        elif msg_type == "target_update":
            logging.log(log_level, f"Status Update (Target): {data.get('target_name', 'N/A')}")
        elif msg_type == "stats":
            logging.log(log_level, f"Status Update (Stats): {data}")
        elif msg_type == "log": # Already contains 'message' and 'level'
            logging.log(log_level, f"Status Update (Log): {log_message_content}")
        else: # Generic fallback
            logging.log(log_level, f"Status Update ({msg_type}): {log_message_content}")
    else:
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
async def initialize_system(args: argparse.Namespace):
    global current_ip, active_target, available_targets, downloaded_urls_in_session, keyword_filters_from_cli

    # Override config with CLI args before full initialization
    if args.config_file:
        # This assumes app_config has a method to load a new config file.
        # If not, this needs to be implemented in config.py
        # For now, let's assume it re-initializes or updates internal config from a file.
        # Example: app_config.load_from_file(args.config_file)
        logging.info(f"Attempting to load custom config from: {args.config_file}")
        # Actual implementation for this depends on how `app_config` is structured.
        # For mock, we can simulate by directly setting if needed, or add a mock method.
        if hasattr(app_config, 'load_config_from_file'):
            app_config.load_config_from_file(args.config_file)
        else:
            logging.warning(f"Custom config file loading not fully implemented in mock/config module for {args.config_file}")


    if args.log_level:
        app_config.set_config('LOG_LEVEL', args.log_level.upper())
        logging.info(f"Log level overridden by CLI to: {args.log_level.upper()}")

    if args.max_concurrent_downloads:
        app_config.set_config('MAX_CONCURRENT_DOWNLOADS', args.max_concurrent_downloads)
        logging.info(f"Max concurrent downloads overridden by CLI to: {args.max_concurrent_downloads}")

    log_dir = app_config.get_config('LOG_DIR', 'logs')
    log_level_str = app_config.get_config('LOG_LEVEL', 'INFO') # Get potentially updated log_level
    log_level_val = getattr(logging, log_level_str.upper(), logging.INFO)

    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)
    log_file_path = os.path.join(log_dir, 'harvester.log')

    utils.setup_logging(log_file_path=log_file_path, level=log_level_val)
    logging.info(f"Logging system initialized. Level: {log_level_str}")


    # Initialize directories based on config (could be influenced by custom config file)
    app_config.initialize_directories() # This should use the potentially updated config
    logging.info("Application directories initialized.")

    # Load downloaded URLs
    downloaded_log_path = app_config.get_config('DOWNLOADED_URLS_LOG') # Path could change if custom config used
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
        if app_config.get_config('REQUIRE_INITIAL_IP_ROTATION', True): # Default to True, meaning it's critical
            raise RuntimeError("Failed to get initial working IP via rotation. Halting application.")
    await update_status('ip_update', {'ip': current_ip}, is_headless=args.headless)

    # Instantiate targets - This part might need to be more dynamic if new targets can be added easily
    # For now, explicitly creating Gutenberg.
    # In a more extensible system, targets might be discovered/loaded via plugins or config.
    gutenberg_target_instance = gutenberg.GutenbergTarget()
    gt_name = await gutenberg_target_instance.get_target_name()
    available_targets = {gt_name: gutenberg_target_instance}
    # Add other potential targets here if they exist and are imported
    # e.g., openstax_target = openstax.OpenStaxTarget(); available_targets[await openstax_target.get_target_name()] = openstax_target

    # Set active target based on CLI args or default
    default_target_name = gt_name # Default to Gutenberg if no CLI arg
    cli_target_name = args.target

    if cli_target_name and cli_target_name in available_targets:
        active_target = available_targets[cli_target_name]
        logging.info(f"Active target set by CLI to: {cli_target_name}")
    elif cli_target_name: # User specified a target but it's not available
        logging.warning(f"CLI specified target '{cli_target_name}' not found. Using default target '{default_target_name}'.")
        active_target = available_targets[default_target_name]
    else: # No CLI target, use default
        active_target = available_targets[default_target_name]
        logging.info(f"Active target defaulted to: {default_target_name}")

    active_target_name_str = await active_target.get_target_name() # Get the actual name from instance
    await update_status('target_update', {'target_name': active_target_name_str}, is_headless=args.headless)

    if args.keywords:
        keyword_filters_from_cli = [kw.strip() for kw in args.keywords.split(',')]
        logging.info(f"Keyword filters set by CLI: {keyword_filters_from_cli}")
    else:
        keyword_filters_from_cli = None # Ensure it's None if not provided

    await update_status('log', {'message': 'System initialized successfully.', 'level': 'INFO'}, is_headless=args.headless)
    await update_status('stats', stats, is_headless=args.headless)


async def harvester_loop(shutdown_event: asyncio.Event, args: argparse.Namespace):
    global current_ip, active_target, stats, keyword_filters_from_cli # Allow modification of these globals

    logging.info("Harvester loop started.")
    if args.headless:
        logging.info("Running in headless mode.")
        # In headless mode, harvester should start automatically.
        harvester_running.set()
        await update_status('log', {'message': 'Harvester process started automatically in headless mode.', 'level': 'INFO'}, is_headless=args.headless)
        # Potentially add logic for headless run duration or item count limit here if those args are added.
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
                    await update_status('log', {'message': 'Harvester process started.', 'level': 'INFO'}, is_headless=args.headless)
                elif command == "STOP":
                    harvester_running.clear()
                    await update_status('log', {'message': 'Harvester process stopped.', 'level': 'INFO'}, is_headless=args.headless)
                elif command == "ROTATE_IP":
                    await update_status('log', {'message': 'Manual IP rotation requested...', 'level': 'INFO'}, is_headless=args.headless)
                    rotation_success = await ip_rotator.rotate_wireguard_ip()
                    if rotation_success:
                        current_ip = await utils.get_current_public_ip(app_config.get_config('IP_CHECK_SERVICE')) # Or from ip_rotator state
                        await update_status('ip_update', {'ip': current_ip}, is_headless=args.headless)
                        await update_status('log', {'message': f'IP rotated successfully. New IP: {current_ip}', 'level': 'INFO'}, is_headless=args.headless)
                    else:
                        await update_status('log', {'message': 'Manual IP rotation failed.', 'level': 'WARNING'}, is_headless=args.headless)
                elif command == "SET_CONFIG": # Usually from TUI
                    settings_to_update = command_item.get("settings", {})
                    for key, value in settings_to_update.items():
                        app_config.set_config(key, value)
                        logging.info(f"Configuration updated via TUI: {key} = {value}")
                    await update_status('log', {'message': f'Settings updated via TUI: {settings_to_update}', 'level': 'INFO'}, is_headless=args.headless)
                elif command == "SET_TARGET": # Usually from TUI
                    target_name = command_item.get("target_name")
                    if target_name in available_targets:
                        active_target = available_targets[target_name]
                        current_active_target_name = await active_target.get_target_name()
                        await update_status('target_update', {'target_name': current_active_target_name}, is_headless=args.headless)
                        await update_status('log', {'message': f'Active target switched via TUI to: {current_active_target_name}', 'level': 'INFO'}, is_headless=args.headless)
                    else:
                        await update_status('log', {'message': f'Attempt to switch to unknown target via TUI: {target_name}', 'level': 'WARNING'}, is_headless=args.headless)
                elif command == "EXIT_APP": # From TUI
                    logging.info("EXIT_APP command received from TUI. Shutting down harvester loop.")
                    shutdown_event.set()
                    break # Exit while loop

            # --- Target Discovery & Download Queueing ---
            if harvester_running.is_set() and active_target:
                # Check if we need more tasks
                if len(active_download_tasks) < app_config.get_config('MAX_CONCURRENT_DOWNLOADS', 1): # This config can be updated by CLI
                    logging.debug(f"Checking for new links. Active tasks: {len(active_download_tasks)}")

                    # Use keyword_filters_from_cli if provided (set during initialize_system)
                    current_keywords = keyword_filters_from_cli
                    # In a more complex scenario, TUI could also update keywords, needing merging logic.
                    # For now, CLI keywords are set at start. TUI cannot change them in this version.

                    new_links = await active_target.discover_links(downloaded_urls_in_session, keyword_filters=current_keywords)

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
                            await update_status('stats', stats, is_headless=args.headless) # Update stats after queueing one
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
                    await update_status('stats', stats, is_headless=args.headless) # Update after each task completion

            # --- Status Updates & Delays ---
            if harvester_running.is_set():
                if active_download_tasks or (not new_links and not active_target.discovery_complete): # If there are tasks or discovery isn't finished
                    # Shorter sleep if actively downloading or still expecting links
                    await asyncio.sleep(0.5)
                else: # No tasks, no new links, and discovery for current target is complete (or no target)
                    if args.headless and active_target and active_target.discovery_complete:
                        logging.info(f"Headless mode: Discovery complete for target '{await active_target.get_target_name()}'. No more links to process.")
                        # Consider exiting if a specific condition for headless run is met (e.g., download N items)
                        # For now, it will keep running if harvester_running is set.
                        # To make it exit after one target is exhausted in headless:
                        # shutdown_event.set()
                        # break
                        # Or, if it should just idle:
                        await asyncio.sleep(random.uniform(
                            app_config.get_config('MIN_WAIT_BETWEEN_BOOKS_SECONDS', 5),
                            app_config.get_config('MAX_WAIT_BETWEEN_BOOKS_SECONDS',15)
                        ))
                    else: # TUI mode or headless and discovery not complete
                        min_wait = app_config.get_config('MIN_WAIT_BETWEEN_BOOKS_SECONDS', 1)
                        max_wait = app_config.get_config('MAX_WAIT_BETWEEN_BOOKS_SECONDS', 2)
                        await asyncio.sleep(random.uniform(min_wait, max_wait))
            else: # Harvester is stopped (e.g. by TUI or if headless was never started)
                await asyncio.sleep(0.2) # Keep command processing responsive

        except asyncio.CancelledError:
            logging.info("Harvester loop cancelled.")
            shutdown_event.set() # Ensure event is set if cancelled externally
            break
        except Exception as e:
            logging.critical(f"Critical error in harvester_loop: {e}", exc_info=True)
            await update_status('log', {'message': f'Critical error in harvester: {e}', 'level': 'CRITICAL'}, is_headless=args.headless)
            await asyncio.sleep(5) # Avoid rapid looping on persistent error

    logging.info("Harvester loop ended.")


async def start_cli_and_harvester(args: argparse.Namespace):
    global cli_args # Make args globally accessible if needed by other parts not directly receiving it
    cli_args = args

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(shutdown(loop, shutdown_event)))

    try:
        await initialize_system(args) # Pass CLI args to initializer

        harvester_task = asyncio.create_task(harvester_loop(shutdown_event, args), name="harvester_loop_task")

        if args.headless:
            logging.info("Running in headless mode. TUI will not be started.")
            # In headless mode, we just wait for the harvester_task.
            # Signal handlers will manage shutdown_event for Ctrl+C.
            await harvester_task
        else:
            # Start TUI
            cli_app = cli_interface.HarvesterApp()
            cli_app.set_queues(command_queue, status_queue)

            logging.info("Starting TUI application in executor...")
            cli_future = loop.run_in_executor(None, cli_app.run)

            done, pending = await asyncio.wait(
                [harvester_task, cli_future],
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in done:
                try:
                    task.result()
                except asyncio.CancelledError:
                    logging.info(f"Task {task.get_name()} was cancelled.")
                except Exception as e:
                    logging.error(f"Task {task.get_name()} failed with exception: {e}", exc_info=True)

            shutdown_event.set() # Signal other task to stop
            for p_task in pending:
                p_task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

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
def main():
    parser = argparse.ArgumentParser(description="Ghost Harvester: Automated digital content collection tool.")
    parser.add_argument(
        "--target",
        type=str,
        help="Specify the initial target to harvest from (e.g., 'gutenberg'). Defaults to the first available target."
    )
    parser.add_argument(
        "--keywords",
        type=str,
        help="Comma-separated list of keywords to filter content discovery (e.g., 'science,history')."
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run the harvester without the TUI, in headless mode. Logs will be the primary output."
    )
    parser.add_argument(
        "--max-concurrent-downloads",
        type=int,
        help="Override the maximum number of concurrent downloads."
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help="Override the logging level (e.g., DEBUG, INFO)."
    )
    parser.add_argument(
        "--config-file",
        type=str,
        help="Path to a custom JSON configuration file to load."
    )
    # Example of a potential future argument for headless mode:
    # parser.add_argument(
    #     "--max-items",
    #     type=int,
    #     help="In headless mode, stop after successfully downloading this many items."
    # )

    args = parser.parse_args()

    # Store args globally if needed by other modules not explicitly passed, though direct passing is preferred.
    # global cli_args
    # cli_args = args

    try:
        asyncio.run(start_cli_and_harvester(args))
    except KeyboardInterrupt:
        logging.info("Harvester shutting down via KeyboardInterrupt (Ctrl+C in main).")
    except Exception as e:
        # Critical errors before logging is set up might not be caught well.
        # Initial logging setup happens in initialize_system.
        # If error happens before that, it might only go to stdout/stderr.
        logging.critical(f"Harvester failed to run due to an unhandled exception in __main__: {e}", exc_info=True)
    finally:
        logging.info("Application has concluded.")

if __name__ == '__main__':
    main()
