import asyncio
import aiohttp
import subprocess
import random
import logging
import aiofiles
import os

# --- Asynchronous Logging Setup ---
async def setup_logging(log_file_path: str = os.path.join('data', 'logs', 'harvester.log')):
    """Sets up asynchronous logging to console and a file."""
    log_dir = os.path.dirname(log_file_path)
    os.makedirs(log_dir, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO) # Default logging level

    # Console Handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File Handler
    file_handler = logging.FileHandler(log_file_path)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    logging.info("Logging setup complete.")

async def run_command(command: list, description: str, timeout: int = 60) -> tuple[bool, str]:
    """
    Asynchronously runs a shell command and logs its output.
    Returns (success: bool, output: str).
    """
    logging.info(f"Executing command: {' '.join(command)} ({description})")
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)

        stdout_str = stdout.decode('utf-8', errors='ignore').strip()
        stderr_str = stderr.decode('utf-8', errors='ignore').strip()

        if process.returncode != 0:
            full_output = f"STDOUT: {stdout_str}\nSTDERR: {stderr_str}" if stdout_str or stderr_str else "No output."
            logging.error(f"Command '{' '.join(command)}' failed (Exit Code: {process.returncode}): {full_output}")
            return False, stderr_str if stderr_str else stdout_str
        else:
            if stdout_str or stderr_str: # Log output only if there's something to show
                logging.debug(f"Command '{' '.join(command)}' succeeded. STDOUT: {stdout_str} STDERR: {stderr_str}")
            return True, stdout_str if stdout_str else stderr_str # Return stdout on success, or stderr if stdout is empty
    except FileNotFoundError:
        logging.error(f"Command '{command[0]}' not found. Ensure it's installed and in PATH.")
        return False, f"Command '{command[0]}' not found."
    except asyncio.TimeoutError:
        logging.error(f"Command '{' '.join(command)}' timed out after {timeout} seconds.")
        # Try to kill the process if it still exists
        if process.returncode is None: # Process hasn't terminated
            try:
                process.kill()
                await process.wait() # Ensure kill is processed
            except ProcessLookupError:
                logging.debug(f"Process {process.pid} already terminated.")
            except Exception as e_kill:
                logging.error(f"Error trying to kill timed-out process {process.pid}: {e_kill}")
        return False, "Command timed out."
    except Exception as e:
        logging.error(f"An unexpected error occurred while running command '{' '.join(command)}': {e}")
        return False, str(e)

async def get_current_public_ip(ip_check_service: str) -> str | None:
    """Asynchronously checks the current public IP address."""
    logging.debug(f"Checking public IP via {ip_check_service}")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(ip_check_service, timeout=10) as response:
                response.raise_for_status()
                ip = (await response.text()).strip()
                logging.debug(f"Public IP detected: {ip}")
                return ip
    except aiohttp.ClientError as e:
        logging.warning(f"Failed to get public IP from {ip_check_service}: {e}")
        return None
    except asyncio.TimeoutError:
        logging.warning(f"IP check service {ip_check_service} timed out.")
        return None
    except Exception as e:
        logging.warning(f"An unexpected error occurred during IP check: {e}")
        return None

def get_random_user_agent() -> str:
    """Returns a random User-Agent string."""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Android 10; Mobile; rv:100.0) Gecko/100.0 Firefox/100.0",
        "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
    ]
    return random.choice(user_agents)

async def read_file_async(file_path: str) -> str:
    """Asynchronously reads content from a file."""
    async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
        content = await f.read()
    return content

async def append_to_file_async(file_path: str, content: str):
    """Asynchronously appends content to a file, creating it if it doesn't exist."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    async with aiofiles.open(file_path, mode='a', encoding='utf-8') as f:
        await f.write(content)
        await f.write('\n') # Ensure newline for log-like files

async def write_file_async(file_path: str, content: str):
    """Asynchronously writes content to a file, overwriting if it exists."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    async with aiofiles.open(file_path, mode='w', encoding='utf-8') as f:
        await f.write(content)
