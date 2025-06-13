13-06-2025 07:57:03 AM BST

Understood. Project structure and creation guidelines for **OPERATION CEREBRAL FRACTURE - SUB-PROJECT GHOST HARVEST (ASYNC FORTRESS)** are now being prototyped. This structure prioritizes modularity, maintainability, and clear separation of concerns, crucial for a stealthy and efficient operation.

---

### Project Structure: `ghost_harvester_v1.0`

```
ghost_harvester_v1.0/
├── src/                                    # Source code for the core application
│   ├── __init__.py
│   ├── main_harvester.py                   # Main asynchronous orchestration logic
│   ├── config.py                           # Centralized configuration (constants, environment parsing)
│   ├── download_manager.py                 # Handles aria2c execution and direct downloads
│   ├── ip_rotator.py                       # Manages WireGuard interface rotation
│   ├── text_converter.py                   # Handles .docx and born-digital .pdf to .txt conversion
│   └── utils.py                            # General utility functions (logging, file ops, etc.)
│
├── wg_configs/                             # Host directory for WireGuard .conf files (mounted into container)
│   ├── wg0.conf
│   ├── wg1.conf
│   └── ...
│
├── data/                                   # Host directory for persistent data (mounted into container)
│   ├── downloaded_corpus/                  # Cleaned .txt files will be stored here
│   │   ├── project_gutenberg/
│   │   │   └── <ebook_id>.txt
│   │   └── openstax/
│   │       └── <textbook_chapter>.txt
│   ├── logs/                               # Application logs (main_harvester, aria2c)
│   │   ├── harvester.log
│   │   └── aria2c_downloads.log
│   ├── state/                              # State files for resuming operations
│   │   ├── downloaded_urls.log             # List of successfully downloaded URLs
│   │   └── failed_urls.log                 # List of URLs that failed after retries
│   └── temp/                               # Temporary files (e.g., downloaded .docx, raw PDF)
│
├── Dockerfile                              # Docker build instructions
├── .env.example                            # Example environment variables for setup
├── requirements.txt                        # Python dependencies
├── README.md                               # Project documentation, setup, and usage
└── run.sh                                  # Convenience script for Docker execution
```

### Guidelines for Creation

**1. Modularity and Separation of Concerns:**

* **Single Responsibility Principle:** Each Python module (`.py` file) should have a single, well-defined responsibility. For example, `ip_rotator.py` should only handle WireGuard operations, not download logic.
* **Clear Interfaces:** Modules should interact through clear, well-defined function calls, minimizing direct access to internal states of other modules.
* **Encapsulation:** Related functions and data should be grouped within classes or well-defined functions to reduce global state.

**2. Asynchronous First Design:**

* **`asyncio` as Core:** All I/O-bound operations (network requests, file I/O, subprocess calls) must be implemented using `asyncio` primitives (`async def`, `await`, `asyncio.gather`, `asyncio.sleep`).
* **Non-blocking Operations:** Ensure no blocking calls are made within `async` functions without explicit `await` for I/O operations or using `loop.run_in_executor` for CPU-bound tasks (though most tasks here are I/O-bound).
* **Asynchronous Subprocess:** Use `asyncio.create_subprocess_exec` for running `aria2c` and `wg-quick`.

**3. Robust Error Handling and Resilience:**

* **Graceful Degradation:** The application should handle failures (e.g., network errors, IP blocks, file conversion errors) gracefully, logging them, retrying where appropriate, and continuing operation.
* **Retry Mechanisms:** Implement exponential backoff or similar strategies for retries on transient errors.
* **State Management:** Utilize `downloaded_urls.log` and `failed_urls.log` to persist state, enabling the application to resume from where it left off, even after restarts or crashes.
* **Health Checks/Monitoring:** Consider integrating basic internal health checks that could be exposed (e.g., via a simple HTTP endpoint within the container) for external monitoring in a more advanced deployment.

**4. Configuration Management:**

* **Environment Variables:** All sensitive information (e.g., API keys, if applicable in future integrations) and deployment-specific settings should be managed via environment variables.
* **`.env` File:** Use `python-dotenv` for local development and for loading default configuration values within the Docker container.
* **Centralized Configuration:** The `config.py` module should define default values and provide functions to load/validate configuration from environment variables.

**5. Logging and Observability:**

* **Comprehensive Logging:** Implement detailed logging (`logging` module) at appropriate levels (DEBUG, INFO, WARNING, ERROR, CRITICAL) for all operations (downloads, IP changes, errors, warnings).
* **Structured Logs (Optional but Recommended):** For large-scale operations, consider outputting logs in JSON format for easier parsing by log aggregation tools.
* **Log Rotation:** If logs are written to disk within the container, ensure they are handled (e.g., mounted to a persistent volume and managed by an external log rotation tool) to prevent excessive disk usage.

**6. Dockerization Best Practices:**

* **Slim Base Image:** Use a minimal base image (e.g., `python:3.9-slim-buster`) to keep the container size small.
* **Multi-stage Builds (Optional):** For complex builds, consider multi-stage Dockerfiles to reduce final image size by separating build dependencies from runtime dependencies.
* **Layer Caching:** Structure the Dockerfile to take advantage of Docker's layer caching, placing frequently changing commands later in the file.
* **Non-root User (Challenging with `wg-quick`):** While generally good practice, `wg-quick` requires root privileges. The chosen solution uses `sudo` and `--privileged` / `CAP_ADD` flags, which is a necessary deviation for this specific functionality in a Red Cell context.
* **Volume Mounting:** Clearly define and use Docker volumes for persistent data (`data/`, `wg_configs/`) to ensure data persists across container restarts and updates.

**7. Security Considerations (Within Red Cell Context):**

* **VPS Isolation:** Assume the VPS is a dedicated, isolated environment.
* **Credentials:** If any API keys are added in the future, ensure they are passed via environment variables, not hardcoded.
* **Network Access Control:** The use of WireGuard nodes implies a controlled egress. Ensure the VPS itself is hardened.

**8. Code Style and Documentation:**

* **PEP 8 Compliance:** Adhere to Python's official style guide (PEP 8) for readability and consistency.
* **Docstrings and Type Hinting:** Provide clear docstrings for all modules, classes, and functions, explaining their purpose, arguments, and return values. Use type hinting for improved code clarity and maintainability.
* **README.md:** A comprehensive `README.md` is essential for setup, configuration, usage instructions, and troubleshooting.

By following these guidelines, the development of **ASYNC FORTRESS** will be structured, efficient, and aligned with the operational requirements of Project Codenamed: OPERATION CEREBRAL FRACTURE.
