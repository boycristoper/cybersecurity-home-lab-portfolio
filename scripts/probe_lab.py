"""Make five TCP connect-and-close probes against the fixed, isolated lab target."""

import socket
import time

TARGET = "192.168.77.20"
PORTS = (21, 22, 445, 3306, 9999)


def main():
    print(f"Lab only: five TCP connections to {TARGET}. No exploit or login is attempted.")
    for port in PORTS:
        try:
            with socket.create_connection((TARGET, port), timeout=1):
                outcome = "TCP connection succeeded"
        except ConnectionRefusedError:
            outcome = "Connection refused"
        except TimeoutError:
            outcome = "Timed out; do not infer filtered with certainty"
        except OSError as error:
            outcome = f"OS error: {error}"
        print(f"{TARGET}:{port}: {outcome}")
        time.sleep(0.2)


if __name__ == "__main__":
    main()
