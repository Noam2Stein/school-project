import threading
from typing import Callable, Any


class Task:
    def __init__(self, name: str, fn: Callable, *args: Any):
        self.name = name
        self._result = None
        self._done = False

        def run():
            try:
                self._result = fn(*args)
            except Exception:
                self._result = "error"
            finally:
                self._done = True

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def is_pending(self) -> bool:
        return not self._done

    def get(self):
        return self._result