import npyscreen # type: ignore
import asyncio
import logging
import collections # For deque
from typing import Any, Dict, Optional

# --- Global Queues (will be instantiated and passed from main_harvester.py) ---
# These are placeholders for development. In the final app, they should be
# properties of the App or passed to forms explicitly.
command_queue: Optional[asyncio.Queue] = None
status_queue: Optional[asyncio.Queue] = None

# --- Mock Config (to be replaced by actual config from src.config) ---
class MockAppSettings:
    MAX_CONCURRENT_DOWNLOADS = 5
    MIN_WAIT_BETWEEN_BOOKS_SECONDS = 10
    RETRY_ATTEMPTS = 3
    IP_ROTATION_THRESHOLD_FAILURES = 50
    # Add other settings as needed for the SettingsForm

mock_app_settings = MockAppSettings()
initial_settings_values: Dict[str, Any] = {
    "MAX_CONCURRENT_DOWNLOADS": mock_app_settings.MAX_CONCURRENT_DOWNLOADS,
    "MIN_WAIT_BETWEEN_BOOKS_SECONDS": mock_app_settings.MIN_WAIT_BETWEEN_BOOKS_SECONDS,
    "RETRY_ATTEMPTS": mock_app_settings.RETRY_ATTEMPTS,
    "IP_ROTATION_THRESHOLD_FAILURES": mock_app_settings.IP_ROTATION_THRESHOLD_FAILURES,
}


# --- Application Forms ---

class MainForm(npyscreen.FormBaseNewWithMenus):
    def create(self):
        self.name = "Ghost Harvester Control Panel"

        # Make the form slightly larger for more content
        self.lines = 28 # Increase height
        self.columns = 100 # Increase width

        # Status Line 1: Current IP
        self.wStatus1 = self.add(npyscreen.FixedText, name="IPLabel", value="Current IP:", relx=2, rely=2)
        self.wCurrentIP = self.add(npyscreen.FixedText, name="CurrentIPDisplay", value="<N/A>", relx=15, rely=2, editable=False)

        # Status Line 2: Active Target
        self.wStatus2 = self.add(npyscreen.FixedText, name="TargetLabel", value="Active Target:", relx=2, rely=3)
        self.wActiveTarget = self.add(npyscreen.FixedText, name="ActiveTargetDisplay", value="<None Selected>", relx=18, rely=3, editable=False)

        # Log Area
        self.wLogArea = self.add(npyscreen.MultiLineEdit,
                                 name="Logs",
                                 value="",
                                 relx=2, rely=5, max_height=10, max_width=96,
                                 editable=False, autowrap=True)
        self._log_buffer = collections.deque(maxlen=200) # Max lines for log area

        # Statistics
        rely_stats = 16
        self.wStatsDiscovered = self.add(npyscreen.TitleText, name="Discovered:", value="0", relx=2, rely=rely_stats, editable=False, begin_entry_at=20)
        self.wStatsInProgress = self.add(npyscreen.TitleText, name="In Progress:", value="0", relx=2, rely=rely_stats+1, editable=False, begin_entry_at=20)
        self.wStatsCompleted = self.add(npyscreen.TitleText, name="Completed:", value="0", relx=2, rely=rely_stats+2, editable=False, begin_entry_at=20)
        self.wStatsFailed = self.add(npyscreen.TitleText, name="Failed:", value="0", relx=50, rely=rely_stats, editable=False, begin_entry_at=70) # Next column
        self.wStatsDiscarded = self.add(npyscreen.TitleText, name="Discarded (PDF):", value="0", relx=50, rely=rely_stats+1, editable=False, begin_entry_at=70)


        # Buttons
        button_rely = rely_stats + 4
        self.bStartStop = self.add(npyscreen.ButtonPress, name="Start Harvester", relx=2, rely=button_rely)
        self.bStartStop.whenPressed = self.on_start_stop_press
        self._harvester_running = False

        self.bSwitchTarget = self.add(npyscreen.ButtonPress, name="Switch Target", relx=20, rely=button_rely)
        self.bSwitchTarget.whenPressed = self.on_switch_target_press

        self.bConfigureSettings = self.add(npyscreen.ButtonPress, name="Configure Settings", relx=38, rely=button_rely)
        self.bConfigureSettings.whenPressed = self.on_configure_settings_press

        self.bForceIPRotation = self.add(npyscreen.ButtonPress, name="Force IP Rotation", relx=58, rely=button_rely)
        self.bForceIPRotation.whenPressed = self.on_force_ip_rotation_press

        self.bExit = self.add(npyscreen.ButtonPress, name="Exit", relx=80, rely=button_rely)
        self.bExit.whenPressed = self.on_exit_press

        # Menu
        self.m = self.new_menu(name="Main Menu")
        self.m.addItem("Start/Stop Harvester", self.on_start_stop_press, shortcut='s')
        self.m.addItem("Switch Target", self.on_switch_target_press, shortcut='t')
        self.m.addItem("Configure Settings", self.on_configure_settings_press, shortcut='c')
        self.m.addItem("Force IP Rotation", self.on_force_ip_rotation_press, shortcut='r')
        self.m.addItem("Exit Application", self.on_exit_press, shortcut='q')

    def while_waiting(self):
        """Called periodically by npyscreen. Used to process status queue."""
        if status_queue:
            try:
                while not status_queue.empty():
                    message = status_queue.get_nowait()
                    self.process_status_message(message)
                    status_queue.task_done() # Important for asyncio.Queue
            except asyncio.QueueEmpty:
                pass # No new messages
            except Exception as e:
                self._add_log_message(f"Error processing status queue: {e}", "ERROR")
        self.display() # Refresh display

    def _add_log_message(self, msg: str, level: str = "INFO"):
        log_entry = f"[{level}] {msg}"
        self._log_buffer.append(log_entry)
        self.wLogArea.values = list(self_log_buffer)
        self.wLogArea.display()

    def process_status_message(self, message: Dict[str, Any]):
        msg_type = message.get("type")
        if msg_type == "ip_update":
            self.wCurrentIP.value = message.get("ip", "<Error>")
            self.wCurrentIP.display()
        elif msg_type == "target_update":
            self.wActiveTarget.value = message.get("target_name", "<Error>")
            self.wActiveTarget.display()
        elif msg_type == "log":
            self._add_log_message(message.get("message", ""), message.get("level", "INFO"))
        elif msg_type == "stats":
            self.wStatsDiscovered.value = str(message.get("discovered", self.wStatsDiscovered.value))
            self.wStatsInProgress.value = str(message.get("in_progress", self.wStatsInProgress.value))
            self.wStatsCompleted.value = str(message.get("completed", self.wStatsCompleted.value))
            self.wStatsFailed.value = str(message.get("failed", self.wStatsFailed.value))
            self.wStatsDiscarded.value = str(message.get("discarded_pdf", self.wStatsDiscarded.value))
            self.wStatsDiscovered.display()
            self.wStatsInProgress.display()
            self.wStatsCompleted.display()
            self.wStatsFailed.display()
            self.wStatsDiscarded.display()
        # Add more message types as needed

    def on_start_stop_press(self):
        if not command_queue: return
        if self._harvester_running:
            asyncio.create_task(command_queue.put({"command": "STOP"}))
            self.bStartStop.name = "Start Harvester"
            self._add_log_message("Stop command sent.", "ACTION")
        else:
            asyncio.create_task(command_queue.put({"command": "START"}))
            self.bStartStop.name = "Stop Harvester"
            self._add_log_message("Start command sent.", "ACTION")
        self._harvester_running = not self._harvester_running
        self.bStartStop.display()

    def on_switch_target_press(self):
        self.parentApp.setNextForm("TargetSelect")
        self.parentApp.switchFormNow()


    def on_configure_settings_press(self):
        self.parentApp.setNextForm("Settings")
        self.parentApp.switchFormNow()

    def on_force_ip_rotation_press(self):
        if not command_queue: return
        asyncio.create_task(command_queue.put({"command": "ROTATE_IP"}))
        self._add_log_message("Force IP rotation command sent.", "ACTION")

    def on_exit_press(self):
        if not command_queue: return
        asyncio.create_task(command_queue.put({"command": "EXIT_APP"}))
        self._add_log_message("Exit command sent. Shutting down UI.", "ACTION")
        self.parentApp.setNextForm(None) # Signal app to exit
        self.parentApp.switchFormNow()


class SettingsForm(npyscreen.ActionForm):
    """Form for configuring application settings."""
    def create(self):
        self.name = "Configure Settings"
        self.wgMaxDownloads = self.add(npyscreen.TitleText, name="Max Concurrent Downloads:", begin_entry_at=40)
        self.wgMinWait = self.add(npyscreen.TitleText, name="Min Wait Between Books (s):", begin_entry_at=40)
        self.wgRetryAttempts = self.add(npyscreen.TitleText, name="Retry Attempts:", begin_entry_at=40)
        self.wgIPRotationThreshold = self.add(npyscreen.TitleText, name="IP Rotation Threshold (Failures):", begin_entry_at=40)

        # Load initial values (from mock_app_settings for now)
        self.wgMaxDownloads.value = str(initial_settings_values.get("MAX_CONCURRENT_DOWNLOADS", 5))
        self.wgMinWait.value = str(initial_settings_values.get("MIN_WAIT_BETWEEN_BOOKS_SECONDS", 10))
        self.wgRetryAttempts.value = str(initial_settings_values.get("RETRY_ATTEMPTS", 3))
        self.wgIPRotationThreshold.value = str(initial_settings_values.get("IP_ROTATION_THRESHOLD_FAILURES", 50))


    def on_ok(self):
        if not command_queue:
            npyscreen.notify_confirm("Error: Command queue not available.", title="Error")
            return

        updated_settings = {}
        try:
            updated_settings["MAX_CONCURRENT_DOWNLOADS"] = int(self.wgMaxDownloads.value)
            updated_settings["MIN_WAIT_BETWEEN_BOOKS_SECONDS"] = int(self.wgMinWait.value)
            updated_settings["RETRY_ATTEMPTS"] = int(self.wgRetryAttempts.value)
            updated_settings["IP_ROTATION_THRESHOLD_FAILURES"] = int(self.wgIPRotationThreshold.value)
        except ValueError:
            npyscreen.notify_confirm("Invalid input. Please enter numbers only.", title="Input Error")
            return

        asyncio.create_task(command_queue.put({
            "command": "SET_CONFIG",
            "settings": updated_settings
        }))
        npyscreen.notify_confirm("Settings sent to harvester.", title="Success")
        self.parentApp.switchFormPrevious()

    def on_cancel(self):
        self.parentApp.switchFormPrevious()


class TargetSelectForm(npyscreen.ActionForm):
    """Form for selecting a download target."""
    def create(self):
        self.name = "Select Download Target"
        # This list would ideally be dynamic, fetched from the backend or config
        self.target_names = ["project_gutenberg", "another_mock_target", "yet_another_target"]
        self.wgTarget = self.add(npyscreen.TitleSelectOne,
                                 name="Available Targets:",
                                 values=self.target_names,
                                 max_height=len(self.target_names) + 1, # Adjust height dynamically
                                 scroll_exit=True)

    def on_ok(self):
        if not command_queue:
            npyscreen.notify_confirm("Error: Command queue not available.", title="Error")
            return

        selected_targets = self.wgTarget.get_selected_objects()
        if selected_targets:
            selected_target_name = selected_targets[0]
            asyncio.create_task(command_queue.put({
                "command": "SET_TARGET",
                "target_name": selected_target_name
            }))
            npyscreen.notify_confirm(f"Target '{selected_target_name}' selection sent.", title="Success")
        else:
            npyscreen.notify_confirm("No target selected.", title="Warning")

        self.parentApp.switchFormPrevious()

    def on_cancel(self):
        self.parentApp.switchFormPrevious()


class HarvesterApp(npyscreen.NPSAppManaged):
    def onStart(self):
        # Set timeout for while_waiting calls (e.g., 100ms)
        self.keypress_timeout_default = 100 # ms

        self.addForm("MAIN", MainForm, name="Ghost Harvester")
        self.addForm("Settings", SettingsForm, name="Settings")
        self.addForm("TargetSelect", TargetSelectForm, name="Select Target")

        # Potentially pass queues to forms if not using global/module-level ones
        # For example:
        # main_form = self.getForm("MAIN")
        # main_form.command_queue = command_queue
        # main_form.status_queue = status_queue
        # ... and so on for other forms.
        # For now, using the module-level placeholders.

    def set_queues(self, cmd_q: asyncio.Queue, stat_q: asyncio.Queue):
        """Method to allow main_harvester to set the queues after app instantiation."""
        global command_queue, status_queue
        command_queue = cmd_q
        status_queue = stat_q
        # You might want to pass these to forms explicitly if they are already created.
        # However, onStart is called before event loop really begins for forms.


# --- Main execution for testing this UI module directly ---
async def ui_test_main():
    """A simple async main to test the UI standalone with dummy queues."""
    global command_queue, status_queue # Use the global ones for this test
    command_queue = asyncio.Queue()
    status_queue = asyncio.Queue()

    app = HarvesterApp()
    app.set_queues(command_queue, status_queue) # Set queues for the app

    # Start a task to simulate backend status updates
    async def mock_backend_updates():
        count = 0
        ips = ["192.168.1.10", "10.0.0.5", "172.16.0.23"]
        targets = ["project_gutenberg", "some_other_site"]
        stats_discovered = 0
        stats_inprogress = 0
        stats_completed = 0
        stats_failed = 0
        stats_discarded_pdf = 0

        while True:
            await asyncio.sleep(2) # Update every 2 seconds

            # Simulate IP change
            if count % 5 == 0:
                await status_queue.put({'type': 'ip_update', 'ip': ips[count // 5 % len(ips)]})

            # Simulate target change (less frequent)
            if count % 10 == 0:
                 await status_queue.put({'type': 'target_update', 'target_name': targets[count // 10 % len(targets)]})

            # Simulate log messages
            await status_queue.put({'type': 'log', 'message': f'Background message {count}. Harvester is running.', 'level': 'DEBUG'})

            # Simulate stats update
            stats_discovered += 10
            stats_inprogress = (stats_inprogress + 1) % 5
            if count % 3 == 0: stats_completed +=1
            if count % 10 == 0 and count > 0: stats_failed +=1
            if count % 15 == 0 and count > 0: stats_discarded_pdf +=1

            await status_queue.put({
                'type': 'stats',
                'discovered': stats_discovered,
                'in_progress': stats_inprogress,
                'completed': stats_completed,
                'failed': stats_failed,
                'discarded_pdf': stats_discarded_pdf
            })

            count += 1

    # Start a task to print commands from the UI (acting as a mock command processor)
    async def mock_command_processor():
        while True:
            cmd = await command_queue.get()
            # In a real app, this would go to the harvester core.
            # For testing, we just print it.
            print(f"UI Test: Command received: {cmd}")
            if cmd.get("command") == "EXIT_APP":
                # If testing UI standalone, NPSAppManaged might not exit loop on setNextForm(None)
                # when run this way without proper event loop integration with npyscreen's own loop.
                # This is more for when npyscreen's run() method is the main blocking call.
                break
            command_queue.task_done()


    # It's tricky to run npyscreen's event loop (app.run()) and asyncio event loop together
    # without special integration. For basic testing, app.run() is blocking.
    # The while_waiting mechanism in MainForm will handle status_queue processing.
    # For commands, they are put onto command_queue, and mock_command_processor will pick them up.

    # To truly test async command putting from UI and async status updates simultaneously
    # with npyscreen, one typically runs npyscreen in a separate thread if its
    # main loop is blocking and doesn't play well with asyncio.run() directly.
    # However, NPSAppManaged is designed to be more cooperative.

    # The key is that npyscreen's while_waiting and event handling happen in its main loop.
    # asyncio.create_task for putting things on queues from button handlers should work
    # as long as an asyncio event loop is running and npyscreen's loop doesn't entirely starve it.

    # For this subtask, focusing on UI structure and queue interaction logic is key.
    # The actual running might need adjustment in main_harvester.py.

    # Start mock tasks
    backend_task = asyncio.create_task(mock_backend_updates())
    command_task = asyncio.create_task(mock_command_processor())

    # This will block until the app exits.
    # npyscreen needs to run in the main thread.
    # If this is run via `python -m asyncio`, then this might work better.
    # For now, let's assume it's run in a context where asyncio loop is default.
    try:
        app.run()
    finally:
        backend_task.cancel()
        command_task.cancel()
        await asyncio.gather(backend_task, command_task, return_exceptions=True)
        print("UI Test Application Ended.")


if __name__ == '__main__':
    print("Running Ghost Harvester CLI UI Test...")
    print("Press Ctrl-C multiple times if it gets stuck during testing, npyscreen can be tricky with asyncio.")
    # To run this test:
    # 1. Ensure npyscreen is installed.
    # 2. Run this file directly: python src/interface/cli_interface.py
    # This basic asyncio.run might not be ideal for npyscreen.
    # A common pattern is to run npyscreen in the main thread and manage asyncio loop separately
    # or use a library that bridges them if NPSAppManaged isn't enough.
    # For now, this is for structure and basic non-blocking queue checks.

    # This `if __name__ == '__main__':` block is primarily for very basic, direct invocation testing.
    # Proper integration will be in main_harvester.py.
    # asyncio.run(ui_test_main())
    # The above line using asyncio.run() with app.run() inside can be problematic.
    # npyscreen.wrapper_basic is often used for simple cases, or running app.run() directly.

    # For this subtask, I will not use asyncio.run() in the __main__ block here,
    # as the primary goal is the UI structure and methods.
    # The `ui_test_main` and its components serve as a reference for how it *could* be tested.
    # The actual execution will be handled by `main_harvester.py`.

    # To make it runnable for a quick visual check without full async integration:
    class TestApp(npyscreen.NPSAppManaged):
        def onStart(self):
            self.keypress_timeout_default = 100
            self.addForm("MAIN", MainForm)
            self.addForm("Settings", SettingsForm)
            self.addForm("TargetSelect", TargetSelectForm)
            # Queues will be None, so queue-dependent actions might log errors or do nothing.

    if __name__ == '__main__':
        print("Starting npyscreen test application for visual inspection (no queue functionality).")
        TestApp().run()
        print("npyscreen test application finished.")
