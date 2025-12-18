# 6.2 Basic types
## 6.2.1 Uint3
```
Uint3 ::= INTEGER (0..7)
```
# 6.3 SPDUs 
## 6.3.45 PKRecipientInfo
```
PKRecipientInfo ::= SEQUENCE {
 recipientId HashedId8,
 encKey EncryptedDataEncryptionKey
}
```