# Ghost Harvester

Ghost Harvester is an automated digital content collection tool designed to download textual data from various online sources. It focuses on anonymity through IP rotation using WireGuard, robust download management, and conversion of diverse file formats into plain text for large-scale data analysis or corpus building.

The primary application code resides in the `src/` directory.

## Core Features

- **IP Rotation:** Dynamically rotates IP addresses using WireGuard VPN connections (via `ip_rotator.py`).
- **Text Conversion:** Converts downloaded files (DOCX, PDF, TXT) into plain text (via `text_converter.py`).
- **Multiple Download Targets:** Supports different content sources (e.g., Project Gutenberg via `targets/gutenberg.py`).
- **Command-Line Interface (TUI):** An `npyscreen`-based terminal user interface for real-time monitoring and control.
- **Headless Operation:** Can be run without the TUI using command-line arguments.
- **Resilient Downloading:** Uses `aria2c` for efficient downloads (via `download_manager.py`).
- **Persistent State:** Logs downloaded URLs to avoid re-downloads.
- **Configurable:** Settings managed via `src/config.py` (and potentially `.env` files or custom config files if `config.py` is adapted). CLI arguments can override some settings.
- **Dockerized:** Can be containerized (Dockerfile provided in `ghost_harvester_v1.1/` can be adapted).

## Project Structure (Simplified)

```
.
├── src/                                    # Source code for the core application
│   ├── __init__.py
│   ├── main_harvester.py                   # Main asynchronous orchestration logic and CLI entry point
│   ├── config.py                           # Centralized configuration
│   ├── download_manager.py                 # Handles aria2c execution and direct downloads
│   ├── ip_rotator.py                       # Manages WireGuard interface rotation
│   ├── text_converter.py                   # Handles .docx and born-digital .pdf to .txt conversion
│   ├── utils.py                            # General utility functions
│   ├── interface/                          # TUI components (e.g., cli_interface.py)
│   └── targets/                            # Modules for specific download sources (e.g., gutenberg.py)
│
├── wg_configs/                             # Recommended host directory for WireGuard .conf files
│   ├── wg0.conf
│   └── ...
│
├── data/                                   # Recommended host directory for persistent data
│   ├── downloaded_corpus/
│   ├── logs/
│   ├── state/
│   └── temp/
│
├── requirements.txt                        # Python dependencies for the main application in src/
├── ghost_harvester_v1.1/                   # Older/alternative version with its own Docker setup
│   ├── Dockerfile                          # Example Dockerfile
│   └── ...
└── README.md                               # This file
```

## Setup and Dependencies

1.  **Clone the repository.**
2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **System Dependencies:**
    *   Ensure `aria2c` is installed and in your PATH for the download manager.
    *   Ensure `wg-quick` and WireGuard tools are installed if using IP rotation.
    *   For text conversion: `libmagic` might be needed for `python-magic` (often used by text converters, though not explicitly in `requirements.txt`, it's a common underlying dependency for file type detection). `Tesseract OCR` might be needed if scanned PDF processing is enhanced.
4.  **WireGuard Configurations:** If using IP rotation, place your WireGuard client configuration files (e.g., `wg0.conf`) in a directory (e.g., `wg_configs/`). The path to these is typically set in `src/config.py` or an environment variable it reads.
5.  **Data Directories:** Create directories for `data/logs`, `data/state`, `data/temp`, `data/downloaded_corpus` or ensure `src/config.py` points to your desired locations and the application has write permissions.

## Usage

The main application is run via `src/main_harvester.py`.

```bash
python src/main_harvester.py [OPTIONS]
```

**Command-Line Options:**

*   `--target <target_name>`: Specify the initial target to harvest from (e.g., `gutenberg`). Defaults to the first available target.
*   `--keywords <"kw1,kw2,...">`: Comma-separated list of keywords to filter content discovery (e.g., `"science fiction,history"`).
*   `--headless`: Run the harvester without the TUI, in headless mode. Logs will be the primary output.
*   `--max-concurrent-downloads <N>`: Override the maximum number of concurrent downloads configured in `src/config.py`.
*   `--log-level <LEVEL>`: Override the logging level (e.g., `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).
*   `--config-file <path>`: Path to a custom JSON-like configuration file (Note: `src/config.py` must be adapted to support loading this).
*   `-h, --help`: Show the help message and exit.

**Examples:**

*   Run with TUI, targeting Gutenberg:
    ```bash
    python src/main_harvester.py --target gutenberg
    ```
*   Run in headless mode, targeting Gutenberg, filtering for "poetry", with DEBUG logging:
    ```bash
    python src/main_harvester.py --headless --target gutenberg --keywords "poetry" --log-level DEBUG
    ```

**TUI Interaction:**

If not run in `--headless` mode, the application will launch a terminal user interface (TUI) where you can:
- Start/Stop the harvesting process.
- Monitor current IP, active target, and download statistics.
- View live logs.
- Manually trigger IP rotation.
- Switch between available targets.
- (Potentially) Configure some settings dynamically.

## Development Guidelines

(These are general guidelines that were considered during development)

**1. Modularity and Separation of Concerns:**
   - Each Python module aims for a single responsibility.
   - Clear interfaces between modules.

**2. Asynchronous First Design (`asyncio`):**
   - Core I/O operations are asynchronous.

**3. Robust Error Handling and Resilience:**
   - Graceful handling of common failures.
   - State management for resuming operations.

**4. Configuration Management:**
   - Centralized configuration in `src/config.py`.
   - CLI overrides for key parameters.
   - (Future) Support for `.env` files or more complex external config files.

**5. Logging and Observability:**
   - Comprehensive logging via the `logging` module.
   - Logs are crucial, especially in headless mode.

**6. Dockerization:**
   - An example `Dockerfile` is available in the `ghost_harvester_v1.1/` directory. This can be adapted to run the current `src/main_harvester.py` application. Key considerations for Docker:
     - Mounting WireGuard configuration directory.
     - Mounting data persistence directory.
     - Ensuring necessary capabilities for `wg-quick` (`--privileged` or specific `--cap-add` flags like `NET_ADMIN`, `SYS_MODULE`).
     - Making `/dev/net/tun` available.

**7. Adding New Targets:**
   - To add a new download source:
     1. Create a new Python module in `src/targets/`.
     2. Implement a class that inherits from `src.targets.base_target.BaseTarget`.
     3. Implement required methods like `get_target_name()` and `discover_links(...)`.
     4. In `src/main_harvester.py`, import your new target class in `initialize_system` and add an instance of it to the `available_targets` dictionary. The key should be the string name that users will use with the `--target` CLI option.

## Security Considerations
- Be mindful of the terms of service of websites you are targeting.
- IP rotation helps with anonymity but is not foolproof.
- Ensure your WireGuard configurations and server are secure.
- When running with `sudo` or high privileges (e.g., in Docker for WireGuard), understand the security implications.
```
