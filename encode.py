from TerminalInterface import *
from asn1 import *

def encodeMessage(msg: bytes) -> None:
    finalBytes = msg
    return finalBytes

if __name__ == "__main__":
    terminal = TerminalInterface()
    terminal.clear()

    user = terminal.input(prompt="payload: ")
    payload = user.encode("utf-8")

    terminal.clear()

    print(encodeMessage(payload))