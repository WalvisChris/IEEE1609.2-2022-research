from pyasn1.type import univ, namedtype, constraint, namedval, tag

# --- 6.2 Basic Types ---
class Uint3(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 7)

class Uint8(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 255)

class Uint16(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 65535)

class Uint32(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 4294967295)

class Uint64(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 18446744073709551615)

class IValue(Uint16):
    pass

class Opaque(univ.OctetString):
    pass

class SequenceOfOctetString(univ.SequenceOf):
    componentType = univ.OctetString()

class SequenceOfUint3(univ.SequenceOf):
    componentType = Uint3()

class SequenceOfUint8(univ.SequenceOf):
    componentType = Uint8()

class SequenceOfUint16(univ.SequenceOf):
    componentType = Uint16()

# --- 6.3 SPDUs ---
class Ieee1609Dot2Data (univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('protocolVersion', Uint8()),
        namedtype.NamedType('content', Ieee1609Dot2Content())
    )

class Ieee1609Dot2Content (univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('unsecureData', Opaque()),
        namedtype.NamedType('signedData', SignedData()),
        namedtype.NamedType('encryptedData', EncryptedData()),
        namedtype.NamedType('signedX509CertificateRequest', Opaque())
        # TODO meer datatypes
    )

class SignedData (univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashId', HashAlgorithm()),
        namedtype.NamedType('tbsData', ToBeSignedData()),
        namedtype.NamedType('signer', SignerIdentifier()),
        namedtype.NamedType('signature', Signature())
    )

class HashAlgorithm(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('sha256', 0),
        ('sha384', 1),
        ('sm3', 2)
        # TODO meer algoritmen
    )

class ToBeSignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('payload', SignedDataPayload()),
        namedtype.NamedType('headerInfo', HeaderInfo())
    )

class SignedDataPayload(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('data', Ieee1609Dot2Data()),
        namedtype.OptionalNamedType('extDataHash', HashedData()),
        namedtype.OptionalNamedType('omitted', univ.Null())
        # TODO meer types
    )

class HashedData(univ.Choice):
    namedValues = namedval.NamedValues(
        ('sha256HashedData', HaIdId32()),
        ('sha364HashedData', HashedId48()),
        ('sm3HashedData', Hashed32())
    )

class HeaderInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('psid', Psid()),
        namedtype.OptionalNamedType('generationTime', Time64()),
        namedtype.OptionalNamedType('expiryTime', Time64()),
        namedtype.OptionalNamedType('generationLocation', ThreeDLocation()),
        namedtype.OptionalNamedType('p2pcdLearningRequest', HashedId3()),
        namedtype.OptionalNamedType('missingCrlIdentifier', MissingCrlIdentifier()),
        namedtype.OptionalNamedType('encryptionKey', EncryptionKey()),
        namedtype.OptionalNamedType('inlineP2pcdRequest', SequenceOfHashedId3()),
        namedtype.OptionalNamedType('requestedCertificate', Certificate()),
        namedtype.OptionalNamedType('pduFunctionalType', PduFunctionalType())
        # TODO meer optionele headerinfo
    )

class Psid(univ.Integer):
    pass

class Time(Uint64):
    pass

class ThreeDLocation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('latitude', Latitude()),
        namedtype.NamedType('longitude', Longitude()),
        namedtype.NamedType('elevtion', Elevation())
    )

class Latitude(NinetyDegreeInt):
    pass

class NinetyDegreeInt(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(-900000000, 900000001)
    # TODO unknown = 900000001

class KnownLatitude(NinetyDegreeInt):
    pass

# TODO class UnknownLatitude()

class Longtitude(OneEightyDegreeInt):
    pass

class OneEightyDegreeInt(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(-1799999999, 1800000001)
    # TODO unknown = 1800000001

class KnownLongitude(OneEightyDegreeInt):
    pass

# TODO class UnknownLongitude()

class Elevtion(Uint16):
    pass

class MissingCrlIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cracaId', HashedId3()),
        namedtype.NamedType('crlSeries', CrlSeries())
    )

class CrlSeries(Uint16):
    pass

class EncryptionKey(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('aes128Ccm', univ.OctetString(subtypeSpec=constraint.ValueRangeConstraint(16, 16))),
        namedtype.NamedType('sm4Ccm', univ.OctetString(subtypeSpec=constraint.ValueRangeConstraint(16, 16)))
        # TODO more algorithms
    )

class PublicEncryptionKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('supportedSymmAlg', SymmAlgorithm()),
        namedtype.NamedType('publicKey', BasePublicEncryptionkey())
    )

class SymmAlgorithm(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('aes128Ccm', 0),
        ('sm4Ccm', 1)
        # TODO meer algoritmen
    )

class BasePublicEncryptionKey(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('eciesNistP256', EccP256CurvePoint()),
        # TODO namedtype.NamedType('eciesBrainpoolP256r1'),
        namedtype.NamedType('ecencSm2', EccP256CurvePoint())
        # TODO more curves
    )

class EccP256CurvePoint(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('x-only', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32))),
        namedtype.NamedType('fill', univ.Null('')),
        namedtype.NamedType('compressed-y-0', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32))),
        namedtype.NamedType('compressed-y-1', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32))),
        namedtype.NamedType('uncompressedP256', univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('x', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32))),
            namedtype.NamedType('y', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32)))
        )))
    )

# --- 6.4 Certificates ---
# --- 6.5 General Headerinfo extension ---
# --- 6.6 Contributed Headerinfo extension ---
# --- 7.3 CRL Verification Entity specification ---
# --- 7.4 CRL IEEE 1609.2 Security envelope ---
# --- 8.4 Datastructures ---