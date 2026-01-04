from lib.TerminalInterface import *
from lib.asn1 import *
import hashlib
import time

terminal = TerminalInterface()
terminal.clear()

payload = terminal.input(prompt="payload: ")

terminal.clear()

payload_bytes = payload.encode('utf-8')

# === HEADER INFO ===
GENERATION_TIME = int(time.time() * 1_000_000)
EXPIRY_TIME = GENERATION_TIME + 10_000_000

headerInfo = HeaderInfo()
headerInfo['psid'] = 0x20
headerInfo['generationTime'] = GENERATION_TIME
headerInfo['expiryTime'] = EXPIRY_TIME

# === HashAlgorithm ===
hashAlg = HashAlgorithm(0)

# === HashedData ===
RAW_HASH_BYTES = hashlib.sha256(payload_bytes).digest()

hashed_data = HashedData()
hashed_data['sha256HashedData'] = RAW_HASH_BYTES

# === SignedDataPayload ===
signed_payload = SignedDataPayload()
signed_payload['extDataHash'] = hashed_data

# === ToBeSignedData ===
tbs_data = ToBeSignedData()
tbs_data['payload'] = signed_payload
tbs_data['headerInfo'] = headerInfo

# === SignerIdentifier ===
signer = SignerIdentifier()
signer['certificate'] = 0x01

# === Signature Points ===
uncompressed = UncompressedP256()
uncompressed['x'] = b'\x02' * 32 # ?
uncompressed['y'] = b'\x03' * 32 # ?

r_point = EccP256CurvePoint()
r_point['uncompressedP256'] = uncompressed
s_bytes = b'\x01' * 32 # ?

# === EcdsaP256Signature ===
ecdsa_sig = EcdsaP256Signature()
ecdsa_sig['rSig'] = r_point
ecdsa_sig['sSig'] = s_bytes # ?

# === SIGNATURE ===
signature = Signature()
signature['ecdsaNistP256Signature'] = ecdsa_sig

# === SIGNED DATA ===
signed_data = SignedData()
signed_data['hashId'] = hashAlg
signed_data['tbsData'] = tbs_data
signed_data['signer'] = signer
signed_data['signature'] = signature

# === Ieee1609Dot2Content ===
ieee_content = Ieee1609Dot2Content()
ieee_content['signedData'] = signed_data

# === Ieee1609Dot2Data ===
ieee_data = Ieee1609Dot2Data()
ieee_data['protocolVersion'] = 3
ieee_data['content'] = ieee_content

# === TESTING ===
terminal.printASN1(ieee_data)