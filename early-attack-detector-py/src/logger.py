import logging
import sys


def setup_custom_logger(name):
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Ignore invalid instruction warnings from evmdasm.disassembler
    logging.getLogger("evmdasm").setLevel(logging.CRITICAL)

    logger = logging.getLogger("root")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    return logger


logger = setup_custom_logger("root")