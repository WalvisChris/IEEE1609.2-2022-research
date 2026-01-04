from lib.TerminalInterface import *
from lib.asn1 import *
import lib.ieee as ieee

CONTENT_TYPES = ["unsecure", "signed", "encrypted", "enveloped"]

if __name__ == "__main__":
    terminal = TerminalInterface()
    terminal.clear()

    payload = terminal.input(prompt="payload: ")

    terminal.clear()

    terminal.textbox(title=(f"payload: {payload}"), title_color="cyan", items=CONTENT_TYPES, numbered=True)
    contentType = int(terminal.input(prompt="> "))

    terminal.clear()

    _text = f"{CONTENT_TYPES[contentType - 1]}] => [{payload}" 
    terminal.UpperHeader(text=_text)

    match contentType:
        case 1:
            terminal.printASN1(ieee.encodeUnsecured(payload))
        case 2:
            terminal.printASN1(ieee.encodeSigned(payload))
        case 3:
            terminal.printASN1(ieee.encodeEncrypted(payload))
        case 4:
            terminal.printASN1(ieee.encodeEnveloped(payload))
        case _:
            terminal.text("Invalid content type.", color="red")