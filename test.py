from lib.TerminalInterface import *
from lib.asn1 import *
import hashlib
import time

terminal = TerminalInterface()
terminal.clear()

payload = terminal.input(prompt="payload: ")

terminal.clear()

payload_bytes = payload.encode('utf-8')

# === PreSharedKeyRecipientInfo ===
pskRecipInfo = PreSharedKeyRecipientInfo(b'\x01\x02\x03\x04\x05\x06\x07\x08') # ?

# === RecipientId ===
recipId = HashedId8(b'\x01\x02\x03\x04\x05\x06\x07\x08') # ?

# === One28BitCcmCiphertext ===
aes128ccm = One28BitCcmCiphertext()
aes128ccm['nonce'] = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C' # ?
aes128ccm['ccmCiphertext'] = payload_bytes # ?

# === SymmetricCiphertext ===
symmCiphertext = SymmetricCiphertext()
symmCiphertext['aes128ccm'] = aes128ccm

# === SymmRecipientInfo ===
symmRecipInfo = SymmRecipientInfo()
symmRecipInfo['recipientId'] = recipId # ?
symmRecipInfo['encKey'] = symmCiphertext

# === EccP256CurvePoint ===
uncompressed = UncompressedP256()
uncompressed['x'] = b'\x02' * 32 # ?
uncompressed['y'] = b'\x03' * 32 # ?

curvePoint = EccP256CurvePoint()
curvePoint['uncompressedP256'] = uncompressed

# === EciesP256EncryptedKey ===
eciesKey = EciesP256EncryptedKey()
eciesKey['v'] = curvePoint
eciesKey['c'] = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10' # ?
eciesKey['t'] = b'\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20' # ?

# === EncryptedDataEncryptionKey ===
encKey = EncryptedDataEncryptionKey()
encKey['eciesNistP256'] = eciesKey

# === PKRecipientInfo ===
certRecipInfo = PKRecipientInfo()
certRecipInfo['recipientId'] = recipId # ?
certRecipInfo['encKey'] = encKey

# === RecipientInfo ===
recipient1 = RecipientInfo()
recipient1['pskRecipInfo'] = pskRecipInfo
recipient1['symmRecipInfo'] = symmRecipInfo
recipient1['certRecipInfo'] = certRecipInfo
recipient1['signedDataRecipInfo'] = certRecipInfo # ?
recipient1['rekRecipInfo'] = certRecipInfo # ?

# === SequenceOfRecipientInfo ===
recipients = SequenceOfRecipientInfo()
recipients.append(recipient1)

# === EncryptedData ===
enc_data = EncryptedData()
enc_data['recipients'] = recipients
enc_data['ciphertext'] = symmCiphertext

# === Ieee1609Dot2Content ===
ieee_content = Ieee1609Dot2Content()
ieee_content['encryptedData'] = enc_data

# === Ieee1609Dot2Data ===
ieee_data = Ieee1609Dot2Data()
ieee_data['protocolVersion'] = 3
ieee_data['content'] = ieee_content

# === TESTING ===
terminal.printASN1(ieee_data)