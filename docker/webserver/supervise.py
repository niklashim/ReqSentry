"""Development-only supervisor for the two production-like local processes."""

import signal
import subprocess
import sys
import time


children = []
stopping = False


def stop(_signum, _frame):
    global stopping
    stopping = True
    for child in children:
        if child.poll() is None:
            child.terminate()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)


def main():
    global stopping
    commands = [
        ["nginx", "-g", "daemon off;"],
        ["/usr/local/bin/reqsentry", "-config", "/etc/reqsentry/config.yaml"],
    ]
    try:
        for command in commands:
            children.append(subprocess.Popen(command))
        failure = False
        while not stopping:
            for child in children:
                code = child.poll()
                if code is not None:
                    print(f"supervisor: process {child.args[0]} exited with {code}", file=sys.stderr, flush=True)
                    failure = True
                    stopping = True
                    break
            if not stopping:
                time.sleep(0.25)
        for child in children:
            if child.poll() is None:
                child.terminate()
        deadline = time.monotonic() + 5
        for child in children:
            try:
                child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        return 1 if failure else 0
    except Exception as exc:
        print(f"supervisor: startup failed: {exc}", file=sys.stderr, flush=True)
        for child in children:
            if child.poll() is None:
                child.terminate()
            child.wait()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
