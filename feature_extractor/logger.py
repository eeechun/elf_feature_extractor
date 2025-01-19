import logging
import os
from datetime import datetime

def get_logger(name: str, feature: str, log_dir: str = "logs") -> logging.Logger:
    """
    Create and configure a logger instance.

    Args:
        name: Logger name
        log_dir: Directory for log files
        feature: Feature to extract

    Returns:
        logging.Logger: Configured logger instance
    """
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    # File handler
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fh = logging.FileHandler(
            os.path.join(log_dir, f"{feature}_extractor_{timestamp}.log")
        )
    fh.setLevel(logging.INFO)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger