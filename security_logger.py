
import logging
from pathlib import Path

# Set up the local security log directory.
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "security_events.log"

# Configure the logger.
logger = logging.getLogger("linux_health_security")
logger.setLevel(logging.INFO)
logger.propagate = False

# Avoid duplicate handlers.
if not logger.handlers:
    handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(handler)


def log_security_event(message, level="WARNING"):
    """Save a timestamped security event."""
    if level == "ERROR":
        logger.error(message)
    elif level == "INFO":
        logger.info(message)
    else:
        logger.warning(message)


def get_recent_events(limit=100):
    """Return the most recent security log entries."""
    if not LOG_FILE.exists():
        return []

    try:
        with LOG_FILE.open("r", encoding="utf-8") as file:
            lines = file.readlines()

        if limit <= 0:
            return []

        return [line.rstrip("\n") for line in lines[-limit:]]

    except OSError as error:
        return [f"Unable to read security event log: {error}"]

