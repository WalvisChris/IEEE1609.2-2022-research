from lib.TerminalInterface import *
from lib.asn1 import *
import lib.ieee as ieee

CONTENT_TYPES = ["unsecure", "signed", "encrypted", "enveloped"]

if __name__ == "__main__":
    terminal = TerminalInterface()
    terminal.clear()

    payload = terminal.input(prompt="payload: ")

    terminal.clear()

    terminal.textbox(title=(f"payload: {payload}"), title_color="cyan", items=["unsecure", "signed", "encrypted", "enveloped"], numbered=True)
    contentType = int(terminal.input(prompt="> "))

    terminal.clear()

    terminal.UpperHeader(text=CONTENT_TYPES[contentType - 1])
    terminal.displayASN1(obj=ieee.encodeMessageTest(payload, terminal))