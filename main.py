from lib.TerminalInterface import *
from lib.asn1 import *
import lib.ieee as ieee

CONTENT_TYPES = ["unsecure", "signed", "encrypted", "enveloped", "DEMO"]

if __name__ == "__main__":
    terminal = TerminalInterface()
    terminal.clear()

    payload = terminal.input(prompt="payload: ")

    terminal.clear()

    terminal.textbox(title=(f"payload: {payload}"), title_color="cyan", items=CONTENT_TYPES, numbered=True)
    contentType = int(terminal.input(prompt="> "))

    terminal.clear()

    terminal.UpperHeader(text=CONTENT_TYPES[contentType - 1])

    match contentType:
        case 1:
            terminal.displayASN1(ieee.encodeUnsecured(payload))
        case 2:
            terminal.displayASN1(ieee.encodeSigned(payload, terminal))
        case 3:
            terminal.displayASN1(ieee.encodeEncrypted(payload))
        case 4:
            terminal.displayASN1(ieee.encodeEnveloped(payload))
        case 5:
            terminal.displayASN1(ieee.encodeMessageTest(payload))
        case _:
            terminal.text("Invalid content type.", color="red")