import sys
import threading
import time
from datetime import datetime


class Spinner:
    def __init__(self, msg="", disable=False):
        self.msg = msg
        self.disable = disable
        self._running = False
        self._thread = None
        self._chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def start(self):
        if self.disable:
            print(f" {self.msg}...")
            return
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self):
        i = 0
        while self._running:
            sys.stdout.write(f"\r {self._chars[i % len(self._chars)]} {self.msg}...")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1

    def stop(self, status="done"):
        if self._running:
            self._running = False
            if self._thread:
                self._thread.join(0.5)
            sys.stdout.write(f"\r{' ' * 60}\r")
            sys.stdout.flush()


class ProgressBar:
    def __init__(self, total, prefix="", width=40):
        self.total = total
        self.prefix = prefix
        self.width = width
        self.current = 0

    def update(self, n=1):
        self.current += n
        self._display()

    def _display(self):
        pct = self.current / self.total if self.total > 0 else 0
        filled = int(self.width * pct)
        bar = "█" * filled + "░" * (self.width - filled)
        sys.stdout.write(f"\r {self.prefix} [{bar}] {self.current}/{self.total}")
        sys.stdout.flush()

    def done(self):
        self._display()
        print()


class Timer:
    def __init__(self):
        self.start = datetime.now()
        self.laps = []

    def lap(self, name=""):
        elapsed = datetime.now() - self.start
        self.laps.append((name, elapsed))
        return elapsed

    def total(self):
        return datetime.now() - self.start

    def summary(self):
        return f"{self.total().total_seconds():.1f}s"
