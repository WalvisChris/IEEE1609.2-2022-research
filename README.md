# 6.2 Basic types
```asn1
Uint3   ::= INTEGER (0..7)
Uint8   ::= INTEGER (0..255)
Uint16  ::= INTEGER (0..65535)
Uint32  ::= INTEGER (0..4294967295)
Uint64  ::= INTEGER (0..18446744073709551615)
IValue  ::= Uint16
Opaque  ::= OCTET STRING
```
# 6.3 SPDUs 
```asn1
PKRecipientInfo ::= SEQUENCE {
 recipientId HashedId8,
 encKey EncryptedDataEncryptionKey
}
```