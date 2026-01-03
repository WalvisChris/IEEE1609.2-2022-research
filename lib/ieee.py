from lib.TerminalInterface import TerminalInterface
import hashlib
import time
from lib.asn1 import *

def encodeMessageTest(payload: str) -> bytes:
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

def encodeUnsecured(payload: str) -> bytes:    
    payload_bytes = payload.encode('utf-8')
    
    ieee_choice = Ieee1609Dot2Content()
    ieee_choice.setComponentByName('unsecureData', Opaque(payload_bytes))

    ieee_data = Ieee1609Dot2Data()
    ieee_data.setComponentByName('protocolVersion', 3)
    ieee_data.setComponentByName('content', ieee_choice)

    finalBytes = ieee_data
    return finalBytes

def encodeSigned(payload: str, terminal: TerminalInterface) -> bytes:
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

    # === SignedData ===
    hashAlg = HashAlgorithm(0)
    
    # DEBUG
    terminal.empty()
    terminal.displayASN1(hashAlg)

    signedPayload = SignedDataPayload()
    signedPayload.setComponentByName('extDataHash', hashedData)

    tbsData = ToBeSignedData()
    tbsData.setComponentByName('payload', signedPayload)
    tbsData.setComponentByName('headerInfo', headerInfo)

    digest_value = b'\x01\x02\x03\x04\x05\x06\x07\x08'

    signer = SignerIdentifier()
    signer.setComponentByName('digest', digest_value)

    # placeholder values
    r_bytes = b'\x01' * 32
    s_bytes = b'\x01' * 32
    x_bytes = b'\x03' * 32
    y_bytes = b'\x04' * 32

    uncompressed = UncompressedP256() 
    uncompressed.setComponentByName('x', x_bytes)
    uncompressed.setComponentByName('y', y_bytes)

    r_point = EccP256CurvePoint()
    r_point.setComponentByName('uncompressedP256', uncompressed)

    EcdsaSignature = EcdsaP256Signature()
    EcdsaSignature.setComponentByName('rSig', r_point)
    EcdsaSignature.setComponentByName('sSig', s_bytes)

    signature = Signature()
    signature.setComponentByName('ecdsaNistP256Signature', EcdsaSignature)

    signed_data = SignedData()
    signed_data.setComponentByName('hashId', hashAlg)
    signed_data.setComponentByName('tbsData', tbsData)
    signed_data.setComponentByName('signer', signer)
    signed_data.setComponentByName('signature', signature)
    
    # DEBUG
    terminal.empty()
    terminal.displayASN1(signed_data)
    
    # === Ieee1609Dot2Data ===
    ieee_choice = Ieee1609Dot2Content()
    ieee_choice.setComponentByName('signedData', signed_data)

    ieee_data = Ieee1609Dot2Data()
    ieee_data.setComponentByName('protocolVersion', 3)
    ieee_data.setComponentByName('content', ieee_choice)

    # DEBUG
    terminal.empty()
    terminal.displayASN1(ieee_data)

    finalBytes = ieee_data
    return finalBytes

def encodeEncrypted(payload: str) -> bytes:
    return b""

def encodeEnveloped(payload: str) -> bytes:
    return b""