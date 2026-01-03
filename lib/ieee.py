from lib.TerminalInterface import TerminalInterface
import hashlib
import time
from lib.asn1 import *

def encodeMessageTest(payload: str, terminal: TerminalInterface) -> bytes:
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

def encodeUnsecured(payload: str, terminal: TerminalInterface) -> bytes:    
    return b""

def encodeSigned(payload: str, terminal: TerminalInterface) -> bytes:
    return b""

def encodeEncrypted(payload: str, terminal: TerminalInterface) -> bytes:
    return b""

def encodeEnveloped(payload: str, terminal: TerminalInterface) -> bytes:
    return b""