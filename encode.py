import hashlib
from TerminalInterface import *
from asn1 import *
import time

def encodeMessage(payload: str) -> None:    
    
    payload_bytes = payload.encode('utf-8')

    GENERATION_TIME = int(time.time() * 1_000_000)
    EXPIRY_TIME = GENERATION_TIME + 10_000_000

    headerInfo = HeaderInfo()
    headerInfo.setComponentByName('psid', 0x20)
    headerInfo.setComponentByName('generationTime', GENERATION_TIME)
    headerInfo.setComponentByName('expiryTime', EXPIRY_TIME)

    RAW_HASH_BYTES = hashlib.sha256(payload_bytes).digest()
    hash = HashedId32(RAW_HASH_BYTES)

    hashedData = HashedData()
    hashedData.setComponentByName('sha256HashedData', hash)

    signedPayload = SignedDataPayload()
    signedPayload.setComponentByName('extDataHash', hashedData)

    tbsData = ToBeSignedData()
    tbsData.setComponentByName('payload', signedPayload)
    tbsData.setComponentByName('headerInfo', headerInfo)
    
    ieee_choice = Ieee1609Dot2Content()
    ieee_choice.setComponentByName('unsecureData', payload)

    ieee_data = Ieee1609Dot2Data()
    ieee_data.setComponentByName('protocolVersion', 3)
    ieee_data.setComponentByName('content', ieee_choice)

    finalBytes = tbsData
    return finalBytes

if __name__ == "__main__":
    terminal = TerminalInterface()
    terminal.clear()

    payload = terminal.input(prompt="payload: ")

    terminal.clear()

    terminal.textbox(title=(f"payload: {payload}"), title_color="cyan", items=["unsecure", "signed", "encrypted", "enveloped"], numbered=True)
    contentType = terminal.input(prompt="> ")

    terminal.clear()

    # terminal.demoLog(title="Result", title_color="cyan", text=encodeMessage(payload))

    terminal.displayASN1(obj=encodeMessage(payload))