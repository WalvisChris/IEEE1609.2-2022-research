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
"""
Headerinfo bevat belangrijk metadata die o.a. gebruikt wordt voor validatie.
Wij maken in deze simulatie alleen gebruik van generation- en expirytime voor tijdscontrole.
PSID word volgens IEEE 1609.12 gedefinieerd als INTEGER.
Wij gebruiken 22031278 (studentnummer) als placeholder voorbeeld.
"""
GENERATION_TIME = int(time.time() * 1_000_000)
EXPIRY_TIME = GENERATION_TIME + 10_000_000

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
RAW_HASH_BYTES = hashlib.sha256(payload_bytes).digest()

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

# DEBUG
terminal.demoLog(title="hashAlg", title_color="cyan", text="")
terminal.printASN1(hashAlg)
terminal.demoLog(title="tbs_data", title_color="cyan", text="")
terminal.printASN1(tbs_data)
terminal.demoLog(title="signer", title_color="cyan", text="")
terminal.printASN1(signer)
terminal.demoLog(title="signature", title_color="cyan", text="")
terminal.printASN1(signature)
terminal.demoLog(title="signed_data", title_color="cyan", text="")
terminal.printASN1(signed_data)
terminal.demoLog(title="exp_cert", title_color="cyan", text="")
terminal.printASN1(exp_cert)
terminal.demoLog(title="tbsCert", title_color="cyan", text="")
terminal.printASN1(tbsCert)
terminal.demoLog(title="certId", title_color="cyan", text="")
terminal.printASN1(certId)

# === Ieee1609Dot2Content ===
ieee_content = Ieee1609Dot2Content()
ieee_content['signedData'] = signed_data

# === Ieee1609Dot2Data ===
ieee_data = Ieee1609Dot2Data()
ieee_data['protocolVersion'] = 3
ieee_data['content'] = ieee_content

# === TESTING ===
terminal.printASN1(ieee_data)