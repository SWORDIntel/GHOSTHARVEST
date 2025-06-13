# Ghost Harvester

## Overview and Objectives

Ghost Harvester is an automated digital content collection tool designed to download textual data from various online sources. It focuses on anonymity through IP rotation using WireGuard, robust download management, and conversion of diverse file formats into plain text for large-scale data analysis or corpus building.

The primary objectives are:
- To provide a resilient and automated way to gather publicly available text-based resources.
- To ensure user privacy and avoid IP-based restrictions by integrating dynamic IP rotation.
- To process and standardize downloaded content into a usable plain text format.
- To offer a user-friendly command-line interface for managing and monitoring the harvesting process.

## Features

- **IP Rotation:** Dynamically rotates IP addresses using WireGuard VPN connections to maintain anonymity and bypass download restrictions.
- **Text Conversion:** Converts downloaded files (DOCX, PDF, TXT) into minimized plain text, discarding images, formatting, and non-textual content. Scanned PDFs (image-based) are identified and discarded.
- **Multiple Download Targets:** Designed to support various content sources. Currently implemented:
    - **Project Gutenberg:** Discovers and downloads text eBooks from Project Gutenberg's catalog.
- **Command-Line Interface (TUI):** An `npyscreen`-based terminal user interface for real-time monitoring, control (start/stop), target switching, configuration changes, and manual IP rotation.
- **Resilient Downloading:** Uses `aria2c` for efficient downloads, with built-in retry mechanisms and IP rotation triggers on repeated failures.
- **Persistent State:** Logs downloaded URLs to avoid re-downloads across sessions.
- **Configurable:** Settings managed via an `.env` file and adjustable through the TUI.
- **Dockerized:** Easy deployment and dependency management using Docker.

## Host-Side Setup

Before running Ghost Harvester via Docker, some host-side setup is required.

### 1. WireGuard Configurations

- Place your WireGuard client configuration files (e.g., `wg0.conf`, `wg1.conf`, etc.) in a dedicated directory on your host machine. This directory will be mounted into the Docker container.
- For example, create `/opt/wg_configs` and put your `.conf` files there:
  ```bash
  sudo mkdir -p /opt/wg_configs
  sudo cp your_wg_configs/*.conf /opt/wg_configs/
  ```
- **Important:** Ensure these configurations are functional and can connect to their respective WireGuard servers from your host or a test environment.

### 2. `.env` File

- Create an `.env` file in a directory that will be mounted into the Docker container (e.g., your project's root or a dedicated config directory).
- Copy the provided `.env.example` to `.env` and customize the settings:
  ```bash
  cp .env.example .env
  ```
- **Key variables to set in `.env`:**
    - `WG_CONFIG_DIR=/etc/wireguard_configs`: This path *inside the container* should match the target mount path for your WireGuard configs. The example `docker run` command uses this.
    - `OUTPUT_DIR=/app/data/downloaded_corpus`: Path *inside the container* where final text files are stored.
    - `TEMP_DIR=/app/data/temp`: Path *inside the container* for temporary downloads.
    - `LOG_DIR=/app/data/logs`: Path *inside the container* for log files.
    - `DOWNLOADED_URLS_LOG=/app/data/state/downloaded_urls.log`: Path to the log of successfully processed URLs.
    - `FAILED_URLS_LOG=/app/data/state/failed_urls.log`: Path to the log of URLs that failed processing.
    - `ARIA2C_LOG=/app/data/logs/aria2c_downloads.log`: Path for aria2c specific logs.
    - `IP_CHECK_SERVICE=https://ifconfig.me/ip`: Service URL to verify public IP.
    - `CATALOG_URL`: URL for the Project Gutenberg catalog file (e.g., `https://www.gutenberg.org/cache/epub/catalog.rdf.zip`).
    - `MAX_CONCURRENT_DOWNLOADS=2`: Number of parallel downloads.
    - `RETRY_ATTEMPTS=3`: Download retry attempts before giving up on a URL.
    - `IP_ROTATION_THRESHOLD_FAILURES=10`: Number of consecutive download failures to trigger an IP rotation.
    - `RETRY_DELAY_SECONDS=5`: Wait time before retrying a failed download.
    - `MIN_WAIT_BETWEEN_BOOKS_SECONDS=5`
    - `MAX_WAIT_BETWEEN_BOOKS_SECONDS=15`
    - `LOG_LEVEL=INFO`: Logging level (e.g., DEBUG, INFO, WARNING).

## Docker Build Instructions

Navigate to the directory containing the `Dockerfile` (i.e., the `ghost_harvester_v1.1` directory) and run:

```bash
docker build -t ghost-harvester:latest .
```

## Docker Run Instructions

To run the Ghost Harvester application, use the following `docker run` command. This command includes necessary privileges for network and WireGuard operations, and volume mounts for persistent data and configurations.

**Command Template:**

```bash
docker run -it --rm --name ghost-harvester \
    --privileged \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_MODULE \
    --device /dev/net/tun:/dev/net/tun \
    -v /path/to/your/host/wg_configs:/etc/wireguard_configs:ro \
    -v /path/to/your/host/data_persistence:/app/data \
    -v /path/to/your/host/.env:/app/.env:ro \
    ghost-harvester:latest
```

**Explanation of flags and volumes:**

-   `-it`: Runs the container in interactive mode with a pseudo-TTY, necessary for the `npyscreen` interface.
-   `--rm`: Automatically removes the container when it exits.
-   `--name ghost-harvester`: Assigns a name to the container for easier management.
-   `--privileged`: Grants extended privileges to the container. **Required for `wg-quick` to manage network interfaces and routes.** Be aware of the security implications.
-   `--cap-add=NET_ADMIN`: Grants network administration capabilities.
-   `--cap-add=SYS_MODULE`: Allows loading kernel modules, which might be needed by WireGuard.
-   `--device /dev/net/tun:/dev/net/tun`: Makes the TUN device available in the container, essential for VPNs.
-   **Volume Mounts (User must customize host paths):**
    -   `-v /path/to/your/host/wg_configs:/etc/wireguard_configs:ro`: Mounts your WireGuard configuration files directory (e.g., `/opt/wg_configs`) into the container at `/etc/wireguard_configs` in read-only mode. **Replace `/path/to/your/host/wg_configs` with the actual path on your host.**
    -   `-v /path/to/your/host/data_persistence:/app/data`: Mounts a directory from your host (e.g., `./data_host`) into the container at `/app/data`. This is crucial for persisting downloaded content, logs, and application state (like the list of downloaded URLs) across container restarts. **Replace `/path/to/your/host/data_persistence` with the actual path on your host.**
    -   `-v /path/to/your/host/.env:/app/.env:ro`: Mounts your `.env` file (e.g., `./.env`) into the container at `/app/.env` in read-only mode. **Replace `/path/to/your/host/.env` with the actual path on your host.**

**Example `docker run` command:**

If you have:
- WireGuard configs in `/opt/wg_nodes` on your host.
- A directory named `data_on_my_host` in your current working directory (`$(pwd)/data_on_my_host`) for persistent data.
- An `.env` file in your current working directory (`$(pwd)/.env`).

Then the command would be:

```bash
docker run -it --rm --name ghost-harvester \
    --privileged \
    --cap-add=NET_ADMIN --cap-add=SYS_MODULE \
    --device /dev/net/tun:/dev/net/tun \
    -v /opt/wg_nodes:/etc/wireguard_configs:ro \
    -v $(pwd)/data_on_my_host:/app/data \
    -v $(pwd)/.env:/app/.env:ro \
    ghost-harvester:latest
```
*Ensure the paths like `$(pwd)/data_on_my_host` and `$(pwd)/.env` correctly resolve to your intended locations before running.*

## Using the Application

Once the container is running, the `npyscreen` based Terminal User Interface (TUI) will launch.

-   **Main Screen:** Displays current IP, active target, live logs, and download statistics.
-   **Buttons:**
    -   `Start Harvester` / `Stop Harvester`: Toggles the content harvesting process.
    -   `Switch Target`: Opens a form to select a different download target (e.g., from Project Gutenberg to another).
    -   `Configure Settings`: Allows viewing and modifying certain application settings dynamically (e.g., `MAX_CONCURRENT_DOWNLOADS`). Changes are applied immediately.
    -   `Force IP Rotation`: Manually triggers a WireGuard IP rotation.
    -   `Exit`: Shuts down the application gracefully.
-   **Navigation:** Use `Tab` to move between widgets, arrow keys for lists/logs, and `Enter` to activate buttons or selections. Menus can also be accessed (often with `Alt` key combinations or specific function keys, depending on your terminal).

## Directory Structure (Inside Container / Mirrored by Host Data Volume)

-   `/app/src/`: Contains the Python source code for the application.
-   `/app/data/`: Main directory for persistent data.
    -   `/app/data/downloaded_corpus/`: Final minimized text files are stored here, organized by target.
    -   `/app/data/logs/`: Contains application logs:
        -   `harvester.log`: Main application log.
        -   `aria2c_downloads.log`: Log file specifically for `aria2c` download activities.
    -   `/app/data/state/`: Stores application state files.
        -   `downloaded_urls.log`: List of URLs successfully downloaded and processed.
        -   `failed_urls.log`: List of URLs that failed to download or process.
    -   `/app/data/temp/`: Temporary storage for ongoing downloads before conversion.
-   `/etc/wireguard_configs/`: (Inside container) Where host WireGuard configs are mounted.

## Troubleshooting

-   **`wg-quick` or WireGuard Issues:**
    -   Ensure `--privileged`, `--cap-add=NET_ADMIN`, `--cap-add=SYS_MODULE`, and `--device /dev/net/tun` are correctly used in `docker run`.
    -   Verify your WireGuard `.conf` files are valid and work outside Docker.
    -   Check container logs for errors related to `wg-quick up/down`.
-   **Network Issues / Cannot Download:**
    -   Verify the container has internet access, possibly through the VPN.
    -   Check the `IP_CHECK_SERVICE` in your `.env` file if IP updates are failing.
    -   Inspect `aria2c_downloads.log` for specific download errors.
-   **Docker Permissions:**
    -   Ensure the directories mounted as volumes (especially the data directory) have correct permissions for the user inside the Docker container (often UID/GID matching the user running `pip install` or the default user in the image). If `aria2c` or Python scripts cannot write to `/app/data`, it's likely a permission issue on the host-mounted volume.
-   **Log Locations:**
    -   Main application log: `/app/data/logs/harvester.log` (inside container, check your host mount).
    -   Aria2c download log: `/app/data/logs/aria2c_downloads.log`.

## Future Enhancements (Potential)

-   Support for more diverse content targets (e.g., forums, specific websites with sitemaps).
-   More sophisticated keyword and metadata filtering options.
-   Integration with content storage solutions (e.g., databases, cloud storage).
-   A web-based UI for remote management as an alternative to the TUI.
-   Advanced scheduling and bandwidth management features.

---
*Remember to replace placeholder paths in Docker commands with your actual host system paths.*
```
