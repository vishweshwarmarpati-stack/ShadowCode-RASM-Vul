from datetime import datetime


class SandboxLogger:

    def __init__(self):
        self.events = []

    def log(
        self,
        stage: str,
        message: str,
        level: str = "INFO",
    ):
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": level,
            "stage": stage,
            "message": message,
        }

        self.events.append(event)

        print(
            f"[{event['level']}] "
            f"[{event['stage']}] "
            f"{event['message']}"
        )

    def get_events(self):
        return self.events.copy()

    def clear(self):
        self.events.clear()


if __name__ == "__main__":

    logger = SandboxLogger()

    logger.log(
        stage="runtime_detection",
        message="Python runtime detected",
    )

    logger.log(
        stage="patch_validation",
        message="Patch is valid",
    )

    logger.log(
        stage="tests",
        message="Tests failed",
        level="ERROR",
    )

    print("\n===== LOG EVENTS =====")

    for event in logger.get_events():
        print(event)