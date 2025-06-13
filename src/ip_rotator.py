import asyncio
import os
import random
import logging
import subprocess

# Assuming src.utils and src.config exist and are importable
# If not, these lines will need adjustment or stubs.
try:
    from src import utils
    from src import config
except ImportError:
    # Fallback for environments where src.utils or src.config might not be fully set up
    # This allows for initial linting/syntax checking without full runtime environment.
    class MockConfig:
        WG_CONFIG_DIR = "./wireguard_configs" # Example default
    config = MockConfig()

    class MockUtils:
        async def get_current_public_ip(self):
            return "127.0.0.1" # Example default
    utils = MockUtils()


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global list to store available WireGuard interface names (e.g., 'wg0', 'wg1')
wireguard_interfaces: list[str] = []
# Global variable to store the currently active WireGuard interface
current_interface: str | None = None

async def init_wireguard_interfaces():
    """
    Discovers .conf files in the WireGuard configuration directory,
    populates a global list of WireGuard interface names, and logs the discovery.
    Handles FileNotFoundError if the directory does not exist.
    """
    global wireguard_interfaces
    wireguard_interfaces = [] # Reset the list
    try:
        logging.info(f"Discovering WireGuard configuration files in {config.WG_CONFIG_DIR}...")
        for filename in os.listdir(config.WG_CONFIG_DIR):
            if filename.endswith(".conf"):
                interface_name = filename[:-5] # Remove .conf extension
                wireguard_interfaces.append(interface_name)
                logging.info(f"Discovered WireGuard interface: {interface_name}")
        if not wireguard_interfaces:
            logging.warning("No WireGuard configuration files found.")
        else:
            logging.info(f"Available WireGuard interfaces: {wireguard_interfaces}")
    except FileNotFoundError:
        logging.error(f"WireGuard configuration directory not found: {config.WG_CONFIG_DIR}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during WireGuard interface initialization: {e}")

async def rotate_wireguard_ip() -> bool:
    """
    Rotates the WireGuard IP by bringing down the current interface (if any),
    selecting a new random interface, bringing it up, and verifying the new IP.

    Returns:
        bool: True if the IP rotation was successful, False otherwise.
    """
    global current_interface
    global wireguard_interfaces

    if not wireguard_interfaces:
        logging.error("No WireGuard interfaces available to rotate.")
        return False

    # Bring down the current interface if one is active
    if current_interface:
        logging.info(f"Bringing down current WireGuard interface: {current_interface}...")
        try:
            process_down = await asyncio.create_subprocess_shell(
                f"sudo wg-quick down {current_interface}",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout_down, stderr_down = await process_down.communicate()
            if process_down.returncode == 0:
                logging.info(f"Successfully brought down {current_interface}.")
            else:
                logging.error(f"Failed to bring down {current_interface}. Error: {stderr_down.decode().strip()}")
                # Continue an attempt to bring up a new one, maybe the interface was already down
        except subprocess.CalledProcessError as e:
            logging.error(f"Error bringing down {current_interface}: {e}")
            # Continue an attempt to bring up a new one
        except Exception as e:
            logging.error(f"An unexpected error occurred while bringing down {current_interface}: {e}")
            # Continue an attempt to bring up a new one

    # Select a new interface, different from the current one if possible
    new_interface = current_interface
    if len(wireguard_interfaces) > 1 and current_interface:
        possible_new_interfaces = [iface for iface in wireguard_interfaces if iface != current_interface]
        if possible_new_interfaces: # Should always be true if len > 1 and current_interface exists
            new_interface = random.choice(possible_new_interfaces)
        else: # Only one interface, or current_interface was not in the list
             new_interface = random.choice(wireguard_interfaces)
    elif wireguard_interfaces: # Only one interface or no current interface
        new_interface = random.choice(wireguard_interfaces)
    else: # Should have been caught by the initial check
        logging.error("No WireGuard interfaces available.")
        return False


    logging.info(f"Attempting to bring up new WireGuard interface: {new_interface}...")
    try:
        process_up = await asyncio.create_subprocess_shell(
            f"sudo wg-quick up {new_interface}",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout_up, stderr_up = await process_up.communicate()

        if process_up.returncode == 0:
            logging.info(f"Successfully brought up {new_interface}.")
            current_interface = new_interface
            logging.info("Waiting for network to stabilize...")
            await asyncio.sleep(5)  # Wait for the network to stabilize

            logging.info("Verifying new public IP address...")
            # Assuming utils.get_current_public_ip() is an async function
            new_ip = await utils.get_current_public_ip()
            if new_ip:
                logging.info(f"Successfully rotated IP. New public IP: {new_ip} via {current_interface}")
                return True
            else:
                logging.error(f"Failed to verify new public IP after switching to {current_interface}.")
                return False
        else:
            logging.error(f"Failed to bring up {new_interface}. Error: {stderr_up.decode().strip()}")
            # Attempt to restore the old interface if one was active and it's different from the failed one
            if current_interface and current_interface != new_interface:
                 logging.info(f"Attempting to restore previous interface: {current_interface}")
                 # This part might be complex if the original 'current_interface' was also the one that failed to come down
                 # For simplicity, we just try to bring it up.
                 # A more robust solution might involve checking its previous state.
                 restore_process = await asyncio.create_subprocess_shell(
                    f"sudo wg-quick up {current_interface}",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                 )
                 await restore_process.communicate()
                 if restore_process.returncode == 0:
                     logging.info(f"Successfully restored {current_interface}.")
                 else:
                     logging.error(f"Failed to restore {current_interface}.")
                     current_interface = None # Mark that we don't have a known active interface
            else:
                current_interface = None # Mark that we don't have a known active interface
            return False
    except subprocess.CalledProcessError as e:
        logging.error(f"Error bringing up {new_interface}: {e}")
        current_interface = None # Mark that we don't have a known active interface
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred while bringing up {new_interface}: {e}")
        current_interface = None # Mark that we don't have a known active interface
        return False

if __name__ == '__main__':
    # Example Usage (requires actual WireGuard setup and config files)
    # Create dummy config files for testing if needed:
    # e.g., in ./wireguard_configs/wg0.conf, ./wireguard_configs/wg1.conf

    # Create a dummy config directory and files for local testing
    if not os.path.exists(config.WG_CONFIG_DIR):
        os.makedirs(config.WG_CONFIG_DIR)
        with open(os.path.join(config.WG_CONFIG_DIR, "wg0.conf"), "w") as f:
            f.write("# Dummy wg0.conf\n")
        with open(os.path.join(config.WG_CONFIG_DIR, "wg1.conf"), "w") as f:
            f.write("# Dummy wg1.conf\n")

    async def main():
        await init_wireguard_interfaces()
        if wireguard_interfaces:
            logging.info("Attempting first IP rotation...")
            success = await rotate_wireguard_ip()
            if success:
                logging.info(f"First rotation successful. Current interface: {current_interface}")
            else:
                logging.error("First rotation failed.")

            # Attempt another rotation if the first was successful
            if success and len(wireguard_interfaces) > 1:
                logging.info("Attempting second IP rotation...")
                success_2 = await rotate_wireguard_ip()
                if success_2:
                    logging.info(f"Second rotation successful. Current interface: {current_interface}")
                else:
                    logging.error("Second rotation failed.")
            elif len(wireguard_interfaces) <= 1:
                logging.info("Not enough interfaces to attempt a second rotation.")
        else:
            logging.info("No interfaces initialized, skipping rotation.")

    # Python 3.7+
    asyncio.run(main())
else:
    # This block is for when the module is imported,
    # ensuring that utils and config are properly available or mocked.
    # The try-except ImportError above handles the initial import.
    # If actual src.utils and src.config are needed at module load time by other modules,
    # this basic mocking might not be sufficient.
    pass
