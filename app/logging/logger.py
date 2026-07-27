import logging
import os


LOG_DIR = "logs"
LOG_FILE = os.path.join(
    LOG_DIR,
    "threat_system.log"
)


os.makedirs(
    LOG_DIR,
    exist_ok=True
)


logger = logging.getLogger(
    "threat_system"
)


logger.setLevel(
    logging.INFO
)


if not logger.handlers:

    file_handler = logging.FileHandler(
        LOG_FILE
    )

    console_handler = logging.StreamHandler()


    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )


    file_handler.setFormatter(
        formatter
    )

    console_handler.setFormatter(
        formatter
    )


    logger.addHandler(
        file_handler
    )

    logger.addHandler(
        console_handler
    )
