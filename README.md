# Table of Content
- 6.2 Basic types
- 6.3 SPDUs
- 6.4 Certificates
- 6.5 General HeaderInfo extension
- 6.6 Contributed HeaderInfo extensions
- 7.3 CRL Verification Entity specification
- 7.4 CRL IEEE 1609.2 Security envelope

# 6.2 Basic types
```asn1
Uint3   ::= INTEGER (0..7)

Uint8   ::= INTEGER (0..255)

Uint16  ::= INTEGER (0..65535)

Uint32  ::= INTEGER (0..4294967295)

Uint64  ::= INTEGER (0..18446744073709551615)

IValue  ::= Uint16

Opaque  ::= OCTET STRING

SequenceOfOctetString   ::= SEQUENCE (SIZE (0..MAX)) OF OCTET STRING (SIZE(0..MAX))

SequenceOfUint3         ::= SEQUENCE OF Uint3

SequenceOfUint8         ::= SEQUENCE OF Uint8

SequenceOfUint16        ::= SEQUENCE OF Uint16
```
# 6.3 Security services protocol data units (SPDUs)
```asn1
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
```
# 6.4 Certificates
```asn1
Certificate ::= CertificateBase (ImplicitCertificate | ExplicitCertificate)
SequenceOfCertificate ::= SEQUENCE OF Certificate
CertificateBase ::= SEQUENCE {
    version     Uint8(3),
    type        CertificateType,
    issuer      IssuerIdentifier,
    toBeSigned  ToBeSignedCertificate,
    signature   Signature OPTIONAL
}
CertificateType ::= ENUMERATED {
    explicit,
    implicit,
    ...
}
ImplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
    type(implicit),
    toBeSigned(WITH COMPONENTS {...,
    verifyKeyIndicator(WITH COMPONENTS {reconstructionValue})
    }),
    signature ABSENT
})
ExplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
    type(explicit),
    toBeSigned(WITH COMPONENTS {...,
    verifyKeyIndicator(WITH COMPONENTS {verificationKey})
    }),
    signature PRESENT
})
IssuerIdentifier ::= CHOICE {
    sha256AndDigest HashedId8,
    self HashAlgorithm,
    ...,
    sha384AndDigest HashedId8,
    sm3AndDigest HashedId8
}
ToBeSignedCertificate ::= SEQUENCE {
    id                      CertificateId,
    cracaId                 HashedId3,
    crlSeries               CrlSeries,
    validityPeriod          ValidityPeriod,
    region                  GeographicRegion OPTIONAL,
    assuranceLevel          SubjectAssurance OPTIONAL,
    appPermissions          SequenceOfPsidSsp OPTIONAL,
    certIssuePermissions    SequenceOfPsidGroupPermissions OPTIONAL,
    certRequestPermissions  SequenceOfPsidGroupPermissions OPTIONAL,
    canRequestRollover      NULL OPTIONAL,
    encryptionKey           PublicEncryptionKey OPTIONAL,
    verifyKeyIndicator      VerificationKeyIndicator,
    ...,
    flags                   BIT STRING {usesCubk (0)} (SIZE (8)) OPTIONAL,
    appExtensions           SequenceOfAppExtensions,
    certIssueExtensions     SequenceOfCertIssueExtensions,
    certRequestExtension
}
CertificateId ::= CHOICE {
    linkageData LinkageData,
    name        Hostname,
    binaryId    OCTET STRING(SIZE(1..64)),
    none        NULL,
    ...
}
LinkageData ::= SEQUENCE {
    iCert               Ivalue,
    linkage-value       LinkageValue,
    group-linkage-value GroupLinkageValue OPTIONAL
}
LinkageValue ::= OCTET STRING (SIZE(9))
GroupLinkageValue ::= SEQUENCE {
    jValue  OCTET STRING (SIZE(4)),
    value   OCTET STRING (SIZE(9))
}
Hostname ::= UTF8String (SIZE(0..255))
ValidityPeriod ::= SEQUENCE {
    start       Time32,
    duration    Duration
}
Time32 ::= Uint32
Duration ::= CHOICE {
    microseconds    Uint16,
    milliseconds    Uint16,
    seconds         Uint16,
    minutes         Uint16,
    hours           Uint16,
    sixtyHours      Uint16,
    years           Uint16
} 
GeographicRegion ::= CHOICE {
    circularRegion      CircularRegion,
    rectangularRegion   SequenceOfRectangularRegion,
    polygonalRegion     PolygonalRegion,
    identifiedRegion    SequenceOfIdentifiedRegion,
    ...
}
CircularRegion ::= SEQUENCE {
    center TwoDLocation,
    radius Uint16
}
TwoDLocation ::= SEQUENCE {
    latitude    Latitude,
    longitude   Longitude
}
RectangularRegion ::= SEQUENCE {
    northWest TwoDLocation,
    southEast TwoDLocation
}
PolygonalRegion ::= SEQUENCE SIZE(3..MAX) OF TwoDLocation
IdentifiedRegion ::= CHOICE {
    countryOnly             UnCountryId,
    countryAndRegions       CountryAndRegions,
    countryAndSubregions    CountryAndSubregions,
    ...
}
UnCountryId ::= Uint16
CountryAndRegions ::= SEQUENCE {
    country UnCountryId,
    regions SequenceOfUint8
}
CountryAndSubregions ::= SEQUENCE {
    country             UnCountryId,
    regionAndSubregions SequenceOfRegionAndSubregions
}
egionAndSubregions ::= SEQUENCE {
 region     Uint8,
 subregions SequenceOfUint16
}
SequenceOfRegionAndSubregions ::= SEQUENCE OF RegionAndSubregions
SubjectAssurance ::= OCTET STRING (SIZE(1))
PsidSsp ::= SEQUENCE {
    psid    Psid,
    ssp     ServiceSpecificPermissions OPTIONAL
}
SequenceOfPsidSsp ::= SEQUENCE OF PsidSsp
ServiceSpecificPermissions ::= CHOICE {
    opaque      OCTET STRING (SIZE(0..MAX)),
    ...,
    bitmapSsp   BitmapSsp
}
BitmapSsp ::= OCTET STRING (SIZE(0..31))
PsidGroupPermissions ::= SEQUENCE {
    subjectPermissions  SubjectPermissions,
    minChainLength      INTEGER DEFAULT 1,
    chainLengthRange    INTEGER DEFAULT 0,
    eeType              EndEntityType DEFAULT {app}
}
SequenceOfPsidGroupPermissions ::= SEQUENCE OF PsidGroupPermissions
SubjectPermissions ::= CHOICE {
    explicit    SequenceOfPsidSspRange,
    all         NULL,
    ...
}
EndEntityType ::= BIT STRING {app (0), enroll (1)} (SIZE (8)) (ALL EXCEPT {})
PsidSspRange ::= SEQUENCE {
    psid        Psid,
    sspRange    SspRange OPTIONAL
}
SequenceOfPsidSspRange ::= SEQUENCE OF PsidSspRange
SspRange ::= CHOICE {
    opaque          SequenceOfOctetString,
    all             NULL,
    ...,
    bitmapSspRange  BitmapSspRange
}
BitmapSspRange ::= SEQUENCE {
    sspValue    OCTET STRING (SIZE(1..32)),
    sspBitmask  OCTET STRING (SIZE(1..32))
}
SequenceOfAppExtensions ::= SEQUENCE (SIZE(1..MAX)) OF AppExtension
ppExtension ::= SEQUENCE {
    id      CERT-EXT-TYPE.&id({SetCertExtensions}),
    content CERT-EXT-TYPE.&App({SetCertExtensions}{@.id})
}
SequenceOfCertIssueExtensions ::= SEQUENCE (SIZE(1..MAX)) OF CertIssueExtension
CertIssueExtension ::= SEQUENCE {
    id CERT-EXT-TYPE.&id({SetCertExtensions}),
    permissions CHOICE {
        specific CERT-EXT-TYPE.&Issue({SetCertExtensions}{@.id}),
        all NULL
    }
}
SequenceOfCertRequestExtensions ::= SEQUENCE (SIZE(1..MAX)) OF CertRequestExtension
CertRequestExtension ::= SEQUENCE {
    id          CERT-EXT-TYPE.&id({SetCertExtensions}),
    permissions CHOICE {
        specific CERT-EXT-TYPE.&Req({SetCertExtensions}{@.id}),
        all NULL
    }  
}
CERT-EXT-TYPE ::= CLASS {
    &id ExtId,
    &App,
    &Issue,
    &Req
}
OperatingOrganizationId ::= OBJECT IDENTIFIER
certExtId-OperatingOrganization ExtId ::= 1
instanceOperatingOrganizationCertExtensions CERT-EXT-TYPE ::= {
    ID      certExtId-OperatingOrganization
    APP     OperatingOrganizationId
    ISSUE   NULL
    REQUEST NULL
}
SetCertExtensions CERT-EXT-TYPE ::= {
    instanceOperatingOrganizationCertExtensions,
    ...
}
VerificationKeyIndicator ::= CHOICE {
    verificationKey     PublicVerificationKey,
    reconstructionValue EccP256CurvePoint,
    ...
}
PublicVerificationKey ::= CHOICE {
    ecdsaNistP256           EccP256CurvePoint,
    ecdsaBraIoolP256r1      EccP256CurvePoint,
    ...,
    ecdsaBrainpoolP384r1    EccP384CurvePoint,
    ecdsaNistP384           EccP384CurvePoint,
    ecsigSm2                EccP256CurvePoint
}
```
# 6.5 General HeaderInfo extension
```asn1
Extension {EXT-TYPE : ExtensionTypes} ::= SEQUENCE {
    id      EXT-TYPE.&extId({ExtensionTypes}),
    content EXT-TYPE.&ExtContent({ExtensionTypes}{@.id})
}
EXT-TYPE ::= CLASS {
    &extId ExtId,
    &ExtContent
}
ExtId ::= INTEGER(0..255)
Ieee1609ContributeHeaderInfoExtension ::= Extension{{Ieee1609HeaderInfoExtensions}}
Ieee1609HeaderInfoExtensionId ::= ExtId
p2pcd8ByteLearningRequestId Ieee1609HeaderInfoExtensionId ::= 1
Ieee1609HeaderInfoExtensions EXT-TYPE ::= {
    {HashedId8 IDENTIFIED BY p2pcd8ByteLearningRequestId},
    ...
}
```
# 6.6 Contributed HeaderInfo extensions
```asn1
EtsiOriginatingHeaderInfoExtension ::= Extension{{
    EtsiTs103097HeaderInfoExtensions
}}
EtsiTs103097HeaderInfoExtensions EXT-TYPE ::= {
    {EtsiTs102941CrlRequest 
        IDENTIFIED BY etsiTs102941CrlRequestId} |
    {EtsiTs102941DeltaCtlRequest
        IDENTIFIIBY etsiTs102941DeltaCtlRequestId},
    ...
EtsiTs102941CrlRequest ::= NULL
etsiTs102941CrlRequestId ExtId ::= 1
EtsiTs102941DeltaCtlRequest ::= NULL
etsiTs102941DeltaCtlRequestId ExtId ::= 2
}
```
# 7.3 CRL Verification Entity specification
CRL = Certificate Revocation List
```asn1

CrlContents ::= SEQUENCE {
    version         Uint8 (1),
    crlSeries       CrlSeries,
    crlCraca        HashedId8,
    issueDate       Time32,
    nextCrl         Time32,
    priorityInfo    CrlPriorityInfo,
    typeSpecific    TypeSpecificCrlContents
}
TypeSpecificCrlContents ::= CHOICE {
    fullHashCrl             ToBeSignedHashIdCrl,
    deltaHashCrl            ToBeSignedHashIdCrl,
    fullLinkedCrl           ToBeSignedLinkageValueCrl,
    deltaLinkedCrl          ToBeSignedLinkageValueCrl,
    ...,
    fullLinkedCrlWithAlg    ToBeSignedLinkageValueCrlWithAlgIdentifier,
    deltaLinkedCrlWithAlg   ToBeSignedLinkageValueCrlWithAlgIdentifier
}
CrlPriorityInfo ::= SEQUENCE {
    priority Uint8 OPTIONAL,
    ...
}
ToBeSignedHashIdCrl ::= SEQUENCE {
    crlSerial   Uint32,
    entries     SequenceOfHashBasedRevocationInfo,
    ...
}
HashBasedRevocationInfo ::= SEQUENCE {
    id      HashedId10,
    expiry  Time32,
    ...
}
ToBeSignedLinkageValueCrl ::= SEQUENCE {
    iRev                Ivalue,
    indexWithinI        Uint8,
    individual          SequenceOfJMaxGroup OPTIONAL,
    groups              SequenceOfGroupCrlEntry OPTIONAL,
    ...,
    groupsSingleSeed    SequenceOfGroupSingleSeedCrlEntry OPTIONAL
}

ToBeSignedLinkageValueCrlWithAlgIdentifier ::= SEQUENCE {
    iRev                Ivalue,
    indexWithinI        Uint8,
    seedEvolution       SeedEvolutionFunctionIdentifier,
    lvGeneration        LvGenerationFunctionIdentifier,
    individual          SequenceOfJMaxGroup OPTIONAL,
    groups              SequenceOfGroupCrlEntry OPTIONAL,
    groupsSingleSeed    SequenceOfGroupSingleSeedCrlEntry OPTIONAL,
    ...
}
JMaxGroup ::= SEQUENCE {
    jmax        Uint8,
    contents    SequenceOfLAGroup,
    ...
}
SequenceOfJMaxGroup ::= SEQUENCE OF JMaxGroup
LAGroup ::= SEQUENCE {
    la1Id       LaId,
    la2Id       LaId,
    contents    SequenceOfIMaxGroup,
    ...
}
SequenceOfLAGroup ::= SEQUENCE OF LAGroup

IMaxGroup ::= SEQUENCE {
    iMax        Uint16,
    contents    SequenceOfIndividualRevocation,
    ...,
    singleSeed  SequenceOfLinkageSeed OPTIONAL
}
SequenceOfIMaxGroup ::= SEQUENCE OF IMaxGroup

IndividualRevocation ::= SEQUENCE {
    linkageSeed1 LinkageSeed,
    linkageSeed2 LinkageSeed,
    ...
}
SequenceOfIndividualRevocation ::= SEQUENCE (SIZE(0..MAX)) OF IndividualRevocation

GroupCrlEntry ::= SEQUENCE {
    iMax            Uint16,
    la1Id           LaId,
    linkageSeed1    LinkageSeed,
    la2Id           LaId,
    linkageSeed2    LinkageSeed,
    ...
}
SequenceOfGroupCrlEntry ::= SEQUENCE OF GroupCrlEntry
LaId ::= OCTET STRING (SIZE(2))
LinkageSeed ::= OCTET STRING (SIZE(16))
SequenceOfLinkageSeed ::= SEQUENCE OF LinkageSeed
ExpansionAlgorithmIdentifier ::= ENUMERATED {
    sha256ForI-aesForJ,
    sm3ForI-sm4ForJ,
    ...
}

GroupSingleSeedCrlEntry ::= SEQUENCE {
    iMax        Uint16,
    laId        LaId,
    linkageSeed LinkageSeed
}
SequenceOfGroupSingleSeedCrlEntry ::= SEQUENCE OF GroupSingleSeedCrlEntry
SeedEvolutionFunctionIdentifier ::= NULL
LvGenerationFunctionIdentifier ::= NULL
```
# 7.4 CRL IEEE 1609.2 Security envelope
```asn1
CrlSsp::= SEQUENCE {
    version         Uint8(1),
    associatedCraca CracaType,
    crls            PermissibleCrls,
    ...
}
CracaType ::= ENUMERATED {isCraca, issuerIsCraca}
PermissibleCrls ::= SEQUENCE OF CrlSeries
CrlPsid ::= Psid(256)
SecuredCrl ::= Ieee1609Dot2Data (WITH COMPONENTS {...,
    content (WI COMPONENTS {
        signedData (WIICOMPONENTS {...,
            tbsData (WITH COMPONENTS {
                payload (WITH COMPONENTS {...,
                    data (WITH COMPONENTS {...,
                        content (WITH COMPONENTS {
                            unsecuredData (CONTAINING CrlContents)
                        })
                    })
                }),
                headerInfo (WITH COMPONENTS {...,
                    psid                    (CrlPsid),
                    generationTime          ABSENT,
                    expiryTime              ABSENT,
                    generationLocation      ABSENT,
                    p2pcdLearningRequest    ABSENT,
                    missingCrlIdentifier    ABSENT,
                    encryptionKey           ABSENT
                })
            })
        })
    })
})
```
# 8.4 Datastructures
```asn1
09dot2Peer2PeIDU ::= SEQUENCE {
    version Uint8(1),
    content CHOICE {
        caCerts CaCertP2pPDU,
        ...
    }
}
CaCertP2pPDU ::= SEQUENCE OF Certificate

```