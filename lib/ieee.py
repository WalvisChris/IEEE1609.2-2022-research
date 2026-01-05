from lib.TerminalInterface import TerminalInterface
import hashlib
import time
from lib.asn1 import *

def encodeUnsecured(payload: str) -> bytes:    
    payload_bytes = payload.encode('utf-8')
    
    ieee_choice = Ieee1609Dot2Content()
    ieee_choice.setComponentByName('unsecureData', Opaque(payload_bytes))

    ieee_data = Ieee1609Dot2Data()
    ieee_data.setComponentByName('protocolVersion', 3)
    ieee_data.setComponentByName('content', ieee_choice)

    finalBytes = ieee_data
    return finalBytes

def encodeSigned(payload: str) -> bytes:
    # Variables
    payload_bytes = payload.encode('utf-8')
    GENERATION_TIME = int(time.time() * 1_000_000)
    EXPIRY_TIME = GENERATION_TIME + 10_000_000
    RAW_HASH_BYTES = hashlib.sha256(payload_bytes).digest()


    # === HEADER INFO ===
    """
    Headerinfo bevat belangrijk metadata die o.a. gebruikt wordt voor validatie.
    Wij maken in deze simulatie alleen gebruik van generation- en expirytime voor tijdscontrole.
    PSID word volgens IEEE 1609.12 gedefinieerd als INTEGER.
    Wij gebruiken 22031278 (studentnummer) als placeholder voorbeeld.
    """
    headerInfo = HeaderInfo()
    headerInfo['psid'] = 22031278 # PLACEHOLDER
    headerInfo['generationTime'] = GENERATION_TIME
    headerInfo['expiryTime'] = EXPIRY_TIME

    # === HashAlgorithm ===
    """
    HashAlgorithm is een enumerator voor verschillende hashfuncties.
    In onze simulaties is 0 = 'sha256'.
    """
    hashAlg = HashAlgorithm(0)

    # === HashedData ===
    """
    HashedData bevat de hash van de payload.
    Wij maken gebruik van SHA256 waarbij een groote van 32 bytes hoort.
    """
    hashed_data = HashedData()
    hashed_data['sha256HashedData'] = RAW_HASH_BYTES

    # === SignedDataPayload ===
    """
    IEEE 1609.2 vereist dat de hash in de SignedDataPayload CHOICE wordt ingepakt.
    """
    signed_payload = SignedDataPayload()
    signed_payload['extDataHash'] = hashed_data

    # === ToBeSignedData ===
    """
    ToBeSignedData is een verzamelen van de payload en headerinfo.
    In ons geval is de payload de signed payload en bevat de headerinfo allen tijdswaarden.
    """
    tbs_data = ToBeSignedData()
    tbs_data['payload'] = signed_payload
    tbs_data['headerInfo'] = headerInfo

    # === Hostname ===
    hostname = Hostname("hostname-placeholder")

    # === CertificateId ===
    certId = CertificateId()
    certId['name'] = hostname

    # === CracaId ===
    cracaId = HashedId3()

    # === CRL Series ===
    crlSeries = Uint16(65535)

    # === Time ===
    t = Uint32(12345)

    # === Duration ===
    d = Duration()
    d['hours'] = Uint16(3)

    # === ValidityPeriod ===
    validPeriod = ValidityPeriod()
    validPeriod['start'] = t
    validPeriod['duration'] = d

    # === ToBeSignedCertificate ===
    tbsCert = ToBeSignedCertificate()
    tbsCert['id'] = certId
    tbsCert['cracaId'] = b'\xAA' * 3 # ?
    tbsCert['crlSeries'] = crlSeries
    tbsCert['validityPeriod'] = validPeriod

    # === ExplicitCertificate ===
    exp_cert = ExplicitCertificate()
    exp_cert['toBeSignedCert'] = tbsCert
    exp_cert['signature'] = 0x20 # ?

    # === Certificate ===
    cert = Certificate()
    cert['explicitCert'] = exp_cert

    # === SequenceOfCertificate ===
    certificate_seq = SequenceOfCertficate()
    certificate_seq.append(cert)

    # === SignerIdentifier ===
    signer = SignerIdentifier()
    signer['certificate'] = certificate_seq

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

    finalBytes = ieee_data
    return finalBytes

def encodeEncrypted(payload: str) -> bytes:
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
    
    finalBytes = ieee_data
    return finalBytes

def encodeEnveloped(payload: str) -> bytes:
    return univ.OctetString("<TODO>")