# 6.2 Basic types
```Uint3 ::= INTEGER (0..7)```
# 6.3 SPDUs 
```PKRecipientInfo ::= SEQUENCE {
 recipientId HashedId8,
 encKey EncryptedDataEncryptionKey
}