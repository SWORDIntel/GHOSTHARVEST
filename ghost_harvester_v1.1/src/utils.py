import asyncio
import logging
import random
import aiohttp
import aiofiles

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def run_command(command: list, description: str):
    """
    Runs a shell command asynchronously.
    Logs the command, description, stdout, and stderr.
    Raises an exception if the command returns a non-zero exit code.
    """
    logger.info(f"Running command ({description}): {' '.join(command)}")
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()

    stdout_str = stdout.decode().strip()
    stderr_str = stderr.decode().strip()

    if stdout_str:
        logger.info(f"Stdout ({description}): {stdout_str}")
    if stderr_str:
        logger.error(f"Stderr ({description}): {stderr_str}")

    if process.returncode != 0:
        raise Exception(f"Command '{' '.join(command)}' failed with exit code {process.returncode}")
    return stdout_str

async def get_current_public_ip():
    """
    Fetches the current public IP address.
    Uses aiohttp to make a request to api.ipify.org.
    Handles potential errors during the request.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://api.ipify.org") as response:
                response.raise_for_status()  # Raise an exception for bad status codes
                ip = await response.text()
                logger.info(f"Current public IP: {ip}")
                return ip.strip()
    except aiohttp.ClientError as e:
        logger.error(f"Error fetching public IP: {e}")
        return None

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.1.1 Safari/603.2.4",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/99.0.1150.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"
]

def get_random_user_agent():
    """
    Returns a random User-Agent string from a predefined list.
    """
    return random.choice(USER_AGENTS)

async def read_file(file_path: str):
    """
    Reads file content asynchronously.
    """
    try:
        async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
            content = await f.read()
            logger.info(f"Successfully read file: {file_path}")
            return content
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        raise

async def append_to_file(file_path: str, content: str):
    """
    Appends content to a file asynchronously.
    """
    try:
        async with aiofiles.open(file_path, mode='a', encoding='utf-8') as f:
            await f.write(content)
            logger.info(f"Successfully appended to file: {file_path}")
    except Exception as e:
        logger.error(f"Error appending to file {file_path}: {e}")
        raise

if __name__ == '__main__':
    # Example Usage (optional - for testing purposes)
    async def main_test():
        # Test run_command
        try:
            await run_command(['echo', 'Hello World'], 'Test Echo')
            # Example of a failing command
            # await run_command(['ls', '/nonexistent'], 'Test Failing LS')
        except Exception as e:
            logger.error(f"Command execution error: {e}")

        # Test get_current_public_ip
        ip = await get_current_public_ip()
        if ip:
            logger.info(f"Fetched IP: {ip}")
        else:
            logger.warning("Could not fetch IP.")

        # Test get_random_user_agent
        ua = get_random_user_agent()
        logger.info(f"Random User Agent: {ua}")

        # Test file operations
        test_file = "test_async_file.txt"
        try:
            await append_to_file(test_file, "Line 1\n")
            await append_to_file(test_file, "Line 2\n")
            content = await read_file(test_file)
            logger.info(f"Test file content:\n{content}")
        except Exception as e:
            logger.error(f"File operation error: {e}")
        finally:
            # Clean up the test file
            import os
            if os.path.exists(test_file):
                os.remove(test_file)
                logger.info(f"Cleaned up {test_file}")

    asyncio.run(main_test())
