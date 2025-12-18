import pyasn1
"""
# https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=10075082

--- 6.2 Basic Types ---
Uint3 ::= INTEGER (0..7)
Uint8 ::= INTEGER (0..255)
Uint16 ::= INTEGER (0..65535)
Uint32 ::= INTEGER (0..4294967295)
Uint64 ::= INTEGER (0..18446744073709551615)
IValue ::= Uint16
Opaque ::= OCTET STRING
SequenceOfOctetString ::= SEQUENCE OF OCTET STRING
SequenceOfUint3 ::= SEQUENCE OF Uint3
SequenceOfUint8 ::= SEQUENCE OF Uint8
SequenceOfUint16 ::= SEQUENCE OF Uint16

--- 6.3 SPDUs ---
Ieee1609Dot2Data ::= SEQUENCE {
    protoclVerion   Uint8(3),
    content         Ieee1609Dot2Content
}
Ieee1609Dot2Content ::= CHOICE {
    unsecuredData                   Opaque,
    signedData                      SignedData,
    encryptedData                   EncryptedData,
    ...,
    signedX509CertificateRequest    Opaque
}
SigendData ::= SEQUENCE {
    hashId      HashAlgorithm,
    tbsData     ToBeSignedData,
    signer      SignerIdentifier,
    signature   Signature
}
HashAlgorithm ::= ENUMERATED {
    sha256,
    ...,
    sha384,
    sm3
}
ToBeSignedData ::= SEQUENCE {
    payload     SignedDataPayload,
    headerInfo  HeaderInfo
}
SignedDataPayload ::= SEQUENCE {
    data        Ieee1609Dot2Data OPTIONAL,
    extDataHash HashedData OPTIONAL,
    ...,
    omitted     NULL OPTIONAL
}
HashedData::= CHOICE {
    sha256HashedData    HaIdId32,
    ...,
    sha384HashedData    HashedId48,
    sm3HashedData       HashedId32
}
HeaderInfo ::= SEQUENCE {
    psid Psid,
    generationTime          Time64 OPTIONAL,
    expiryTime              Time64 OPTIONAL,
    generationLocation      ThreeDLocation OPTIONAL,
    p2pcdLearningRequest    HashedId3 OPTIONAL,
    missingCrlIdentifier    MissingCrlIdentifier OPTIONAL,
    encryptionKey           EncryptionKey OPTIONAL,
    ...,
    inlineP2pcdRequest      SequenceOfHashedId3 OPTIONAL,
    requestedCertificate    Certificate OPTIONAL,
    pduFunctionalType       PduFunctionalType OPTIONAL,
}
Psid ::= INTEGER (0..MAX)
Time64 ::= Uint64
ThreeDLocation ::= SEQUENCE {
    latitude    Latitude,
    longitude   Longitude,
    elevation   Elevation
}
Latitude ::= NinetyDegreeInt
NinetyDegreeInt ::= INTEGER {
    min (-900000000),
    max (900000000),
    unknown (900000001)
}
KnownLatitude ::= NinetyDegreeInt (min..max)
UnknownLatitude ::= NinetyDegreeInt (unknown)
Longitude ::= OneEightyDegreeInt
OneEightyDegreeInt ::= INTEGER {
    min (-1799999999),
    max (1800000000),
    unknown (1800000001)
} (-1799999999..1800000001)
KnownLongitude ::= OneEightyDegreeInt (min..max)
UnknownLongitude ::= OneEightyDegreeInt (unknown)
Elevation ::= Uint16
MissingCrlIdentifier ::= SEQUENCE {
    cracaId HashedId3,
    crlSeries ,
    ...
}
CrlSeries ::= Uint16
EncryptionKey ::= CHOICE {
    public      PublicEncryptionKey,
    symmetric   SymmetricEncryptionKey
}
SymmetricEncryptionKey ::= CHOICE {
    aes128Ccm OCTET STRING(SIZE(16)),
    ...,
    sm4Ccm OCTET STRING(SIZE(16))
}
PublicEncryptionKey ::= SEQUENCE {
    supportedSymmAlg SymmAlgorithm,
    publicKey BasePublicEncryptionKey
}
SymmAlgorithm ::= ENUMERATED{
    aes128Ccm,
    ...,
    sm4Ccm
}
BasePublicEncryptionKey ::= CHOICE {
    eciesNistP256   EccP256CurvePoint,
    eciesBrainpoolP256r1,
    ...,
    ecencSm2        EccP256CurvePoint
}
ccP256CurvePoint::= CHOICE {
    x-only          OCTET STRING (SIZE (32)),
    fill            NULL,
    compressed-y-0  OCTET STRING (SIZE (32)),
    compressed-y-1  OCTET STRING (SIZE (32)),
    uncompressedP256 SEQUENCE {
        x OCTET STRING (SIZE (32)),
        y OCTET STRING (SIZE (32))
    }
}
EccP384CurvePoint::= CHOICE {
    x-only          OCTET STRING (SIZE (48)),
    fill            NULL,
    compressed-y-0  OCTET STRING (SIZE (48)),
    compressed-y-1  OCTET STRING (SIZE (48)),
    uncompressedP384 SEQUENCE {
        x OCTET STRING (SIZE (48)),
        y OCTET STRING (SIZE (48))
    }
}
PduFunctionalType ::= INTEGER (0..255)
tlsHandshake PduFunctionalType ::= 1
iso21177ExtendedAuth PduFunctionalType ::= 2
iso21177SessionExtension PduFunctionalType ::= 3
ContributedExtensionBlocks ::= SEQUENCE (SIZE(1..MAX)) OF ContributedExtensionBlock
ContributedExtensionBlock ::= SEQUENCE {
    contributorId IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.&id({
        Ieee1609Dot2HeaderInfoContributedExtensions
    }),
    extns  SEQUENCE (SIZE(1..MAX)) OF IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.&Extn({
        Ieee1609Dot2HeaderInfoContributedExtensions
    }{@.contributorId})
}
1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION ::= CLASS {
    &id HeaderInfoContributorId UNIQUE,
    &Extn
} WITH SYNTAX {&Extn IDENTIFIED BY &id}
Ieee1609Dot2HeaderInfoContributedExtensions
    IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION ::= {
        {Ieee1609ContributedHeaderInfoExtension IDENTIFIED BY ieee1609HeaderInfoContributorId} |
        {EtsiOriginatingHeaderInfoExtension IDENTIFIED BY etsiHeaderInfoContributorId},
    ...
}
HeaderInfoContributorId ::= INTEGER (0..255)
ieee1609HeaderInfoContributorId HeaderInfoContributorId ::= 1
etsiHeaderInfoContributorId HeaderInfoContributorId ::= 2
SignerIdentifier ::= CHOICE {
    digest      HashedId8,
    certificate SequenceOfCertificate,
    self        NULL,
    ...
}
HashedId3 ::= OCTET STRING (SIZE(3))
SequenceOfHashedId3 ::= SEQUENCE OF HashedId3
HashedId8 ::= OCTET STRING (SIZE(8))
HashedId10 ::= OCTET STRING (SIZE(10))
HashedId32 ::= OCTET STRING (SIZE(32))
HashedId48 ::= OCTET STRING (SIZE(48))
Signature ::= CHOICE {
    ecdsaNistP256Signature          EcdsaP256Signature,
    ecdsaBrainpoolP256r1Signature   EcdsaP256Signature,
    ...,
    ecdsaBrainpoolP384r1Signature   EcdsaP384Signature,
    ecdsaNistP384Signature          EcdsaP384Signature,
    sm2Signature                    EcsigP256Signature
}
EcdsaP256Signature ::= SEQUENCE {
    rSig EccP256CurvePoint,
    sSig OCTET STRING (SIZE (32))
}
EcdsaP384Signature ::= SEQUENCE {
    rSig EccP384CurvePoint,
    sSig OCTET STRING (SIZE (48))
}
EcsigP256Signature ::= SEQUENCE {
    rSig OCTET STRING (SIZE (32)),
    sSig OCTET STRING (SIZE (32))
}
EncryptedData ::= SEQUENCE {
    recipients SequenceOfRecipientInfo,
    ciphertext SymmetricCiphertext
}
RecipientInfo ::= CHOICE {
    pskRecipInfo        PreSharedKeyRecipientInfo,
    symmRecipInfo       SymmRecipientInfo,
    certRecipInfo       PKRecipientInfo,
    signedDataRecipInfo PKRecipientInfo,
    rekRecipInfo        PKRecipientInfo
}
PreSharedKeyRecipientInfo ::= HashedId8
SymmRecipientInfo ::= SEQUENCE {
    recipientId HashedId8,
    encKey      SymmetricCiphertext
}
PKRecipientInfo ::= SEQUENCE {
    recipientId HashedId8,
    encKey      EncryptedDataEncryptionKey
}
EncryptedDataEncryptionKey ::= CHOICE {
    eciesNistP256           EciesP256EncryptedKey,
    eciesBrainpoolP256r1    EciesP256EncryptedKey,
    ...,
    ecencSm2256             EcencP256EncryptedKey
}
EciesP256EncryptedKey ::= SEQUENCE {
    v EccP256CurvePoint,
    c OCTET STRING (SIZE (16)),
    t OCTET STRING (SIZE (16))
}
EcencP256EncryptedKey ::= SEQUENCE {
    v EccP256CurvePoint,
    c OCTET STRING (SIZE (16)),
    t OCTET STRING (SIZE (32))
}
SymmetricCiphertext ::= CHOICE {
    aes128ccm   One28BitCcmCiphertext,
    ...,
    sm4Ccm      One28BitCcmCiphertext
}
One28BitCcmCiphertext ::= SEQUENCE {
    nonce           OCTET STRING (SIZE (12)),
    ccmCiphertext   Opaque
}
Countersignature ::= IeeI1609Dot2Data (WITH COMPONENTS {...,
    content (WITH COMPONENTS {...,
        signedData (WITH COMPONENTS {...,
            tbsData (WITH COMPONENTS {...,
                payload (WITH COMPONENTS {...,
                    data ABSENT,
                    extDataHash PRESENT
                }),
                headerInfo(WITH COMPONENTS {...,
                    generationTime PRESENT,
                    expiryTime ABSENT,
                    generationLocation ABSENT,
                    p2pcdLearningRequest ABSENT,
                    missingCrlIdentifier ABSENT,
                    encryptionKey ABSENT
                })
            })
        })
    })
})

--- 6.4 certificates ---
"""