from pyasn1.type import univ, namedtype, constraint, namedval, char, tag

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
        ('sm3HashedData', HashedId32())
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

class Longitude(OneEightyDegreeInt):
    pass

class OneEightyDegreeInt(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(-1799999999, 1800000001)
    # TODO unknown = 1800000001

class KnownLongitude(OneEightyDegreeInt):
    pass

# TODO class UnknownLongitude()

class Elevation(Uint16):
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
        namedtype.NamedType('publicKey', BasePublicEncryptionKey())
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

class EccP384CurvePoint(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('x-only', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(48, 48))),
        namedtype.NamedType('fill', univ.Null('')),
        namedtype.NamedType('compressed-y-0', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(48, 48))),
        namedtype.NamedType('compressed-y-1', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(48, 48))),
        namedtype.NamedType('uncompressedP384', univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('x', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(48, 48))),
            namedtype.NamedType('y', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(48, 48)))
        )))
    )

class PduFunctionalType(Uint8):
    pass

class PduFunctionalType(Uint8):
    namedValues = namedval.NamedValues(
        ('tlsHandshake', 1),
        ('iso21177ExtendedAuth', 2),
        ('iso21177SessionExtension', 3)
    )

# class ContributedExtesionBlocks(univ.Sequence):

# class ContributedExtensionBlock(univ.Sequence):

# class 1609Dot2-HEADERINFO-CONTRIBUTED-EXTESNION():

# class Ieee1609Dot2HeaderInfoCOntributedExtensions():

class HeaderInfoContributorId(Uint8):
    namedValues = namedval.NamedValues(
        ('ieee1609HeaderInfoContributorId', 1),
        ('etsiHeaderInfoContributorId', 2)
    )

class SignerIdentifier(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('digest', HashedId8()),
        ('certificate', SequenceOfCertificate()),
        ('self', univ.Null())
    )

class HashedId3(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(3, 3)

class SequenceOfHashedId3(univ.SequenceOf):
    componentType = HashedId3()

class HashedId8(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(8, 8)

class HashedId10(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(10, 10)

class HashedId32(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(32, 32)

class HashedId48(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(48, 48)

class Signature(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('ecdsaNistP256Signature', EcdsaP256Signature()),
        ('ecdsaBrainpoolP245r1Signature', EcdsaP256Signature()),
        ('ecdsaBrainpoolP384r1Signature', EcdsaP384Signature()),
        ('ecdsaNist384Signature', EcdsaP384Signature()),
        ('sm2Signature', EcdsaP256Signature()),
        # TODO more
    )

class EcdsaP256Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('rSig', EccP256CurvePoint()),
        namedtype.NamedType('sSig', HashedId32())
    )

class EcdsaP384Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('rSig', EccP384CurvePoint()),
        namedtype.NamedType('sSig', HashedId48())
    )

class EcsigP256Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('rSig', HashedId32()),
        namedtype.NamedType('sSig', HashedId32())
    )

class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipients', SequenceOfRecipientInfo()),
        namedtype.NamedTypes('ciphertext', SymmetricCiphertext())
    )

class RecipientInfo(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('pskRecipInfo', PreSharedKeyRecipientInfo()),
        ('symmRecipInfo', SymmRecipientInfo()),
        ('certRecipInfo', PKRecipientInfo()),
        ('signedDataRecipInfo', PKRecipientInfo()),
        ('rekRecipInfo', PKRecipientInfo())
    )

class SequenceOfRecipientInfo(univ.SequenceOf):
    componentType = RecipientInfo()

class PreSharedKeyRecipientInfo(HashedId8):
    pass

class SymmRecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipientId', HashedId8()),
        namedtype.NamedType('encKey', SymmetricCiphertext())
    )

class PKRecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipientId', HashedId8()),
        namedtype.NamedType('encKey', EncryptedDataEncryptionKey())
    )

class EncryptedDataEncryptionKey(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('eciesNistP256', EciesP256EncryptedKey()),
        ('eciesBrainpoolP256r1', EciesP256EncryptedKey()),
        ('ecencSm2256', EcencP256EncryptedKey())
        # TODO more
    )

class EciesP256EncryptedKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('v', EccP256CurvePoint()),
        namedtype.NamedType('c', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(16, 16))),
        namedtype.NamedType('t', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(16, 16)))
    )

class EcencP256EncryptedKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('v', EccP256CurvePoint()),
        namedtype.NamedType('c', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(16, 16))),
        namedtype.NamedType('t', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32)))
    )

class SymmetricCiphertext(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('aes128ccm', One28BitCcmCiphertext()),
        ('sm4Ccm', One28BitCcmCiphertext())
        # TODO more
    )

class One28BitCcmCiphertext(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('nonce', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(12, 12))),
        namedtype.NamedType('ccmCiphertext', Opaque())
    )

class Countersignature(Ieee1609Dot2Data):
    subtypeSpec = constraint.ConstraintsIntersection(
        Ieee1609Dot2Data.subtypeSpec,
        constraint.ComponentPresentConstraint(
            'content',
            constraint.ComponentPresentConstraint(
                'signedData',
                constraint.ComponentPresentConstraint(
                    'tbsData',
                    constraint.ConstraintsIntersection(
                        constraint.ComponentPresentConstraint(
                            'payload',
                            constraint.ConstraintsIntersection(
                                constraint.ComponentAbsentConstraint('data'),
                                constraint.ComponentPresentConstraint('extDataHash')
                            )
                        ),
                        constraint.ComponentPresentConstraint(
                            'headerInfo',
                            constraint.ConstraintsIntersection(
                                constraint.ComponentPresentConstraint('generationTime'),
                                constraint.ComponentAbsentConstraint('expiryTime'),
                                constraint.ComponentAbsentConstraint('generationLocation'),
                                constraint.ComponentAbsentConstraint('p2pcdLearningRequest'),
                                constraint.ComponentAbsentConstraint('missingCrlIdentifier'),
                                constraint.ComponentAbsentConstraint('encryptionKey')
                            )
                        )
                    )
                )
            )
        )
    )

# --- 6.4 Certificates ---
Certificate = CertificateBase

class SequenceOfCertificateBase(univ.SequenceOf):
    componentType = Certificate()

class CertificateBase(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version',  Uint8()),
        namedtype.NamedType('type', CertificateType()),
        namedtype.NamedType('issuer', IssuerIdentifier()),
        namedtype.NamedType('toBeSigned', ToBeSignedCertificate()),
        namedtype.OptionalNamedType('signature', Signature())
    )

class CertificateType(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('explicit', 0),
        ('implicit', 1)
    )

class ImplicitCertificate(CertificateBase):
    subtypeSpec = constraint.ConstraintsIntersection(
        CertificateBase.subtypeSpec,
        constraint.ComponentValueConstraint('type', CertificateType('implicit')),
        constraint.ComponentPresentConstraint('toBeSigned', constraint.ComponentPresentConstraint('verifyKeyIndicator', constraint.ComponentPresentConstraint('reconstructionValue'))),
        constraint.ComponentAbsentConstraint('signature')
    )

class ExplicitCertificate(CertificateBase):
    subtypeSpec = constraint.ConstraintsIntersection(
        CertificateBase.subtypeSpec,
        constraint.ComponentValueConstraint('type', CertificateType('explicit')),
        constraint.ComponentPresentConstraint('toBeSigned', constraint.ComponentPresentConstraint('verifyKeyIndicator', constraint.ComponentPresentConstraint('verificationKey'))),
        constraint.ComponentPresentConstraint('signature')
    )

class IssueIdentifier(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('sha256AndDigest', HashedId8()),
        ('self', HashAlgorithm()),
        ('sha384AndDigest', HashedId8()),
        ('sm3AndDigest', HashedId8())
        # TODO more
    )

class ToBeSignedCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', CertificateId()),
        namedtype.NamedType('cracaId', HashedId3()),
        namedtype.NamedType('crlSeries', CrlSeries()),
        namedtype.NamedType('validityPeriod', ValidityPeriod()),
        namedtype.OptionalNamedType('region', GeographicRegion()),
        namedtype.OptionalNamedType('assuranceLevel', SubjectAssurance()),
        namedtype.OptionalNamedType('appPermissions', SequenceOfPsidSsp()),
        namedtype.OptionalNamedType('certIssuePermissions', SequenceOfPsidGroupPermissions()),
        namedtype.OptionalNamedType('certRequestPermissions', SequenceOfPsidGroupPermissions()),
        namedtype.OptionalNamedType('canRequestRollover', univ.Null()),
        namedtype.OptionalNamedType('encryptionKey', PublicEncryptionKey()),
        namedtype.NamedType('verifyKeyIndicator', VerificationKeyIndicator()),
        # namedtype.OptionalNamedType('flags', ),
        namedtype.NamedType('appExtensions', SequenceOfAppExtensions()),
        namedtype.NamedType('certIssueExtensions', SequenceOfCertIssueExtensions())
        # namedtype.NamedType('certRequestExtension')
    )

class CertificateId(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('linkageData', LinkageData()),
        ('name', Hostname()),
        ('binaryId', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(1, 64))),
        ('none', univ.Null())
    )

class LinkageData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('iCert', IValue()),
        namedtype.NamedType('linkage-value', LinkageValue()),
        namedtype.OptionalNamedType('group-linkage-value', GroupLinkageValue())
    )

class LinkageValue(univ.OctetString):
    subtypeSpec=constraint.ValueRangeConstraint(9, 9)

class GroupLinkageValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('jValue', univ.OctetString(subtypeSpec=constraint.ValueRangeConstraint(4, 4))),
        namedtype.NamedType('Value', univ.OctetString(subtypeSpec=constraint.ValueRangeConstraint(9, 9)))
    )

class Hostname(char.UTF8String):
    subtypeSpec = constraint.ValueRangeConstraint(0, 255)

class ValidityPeriod(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('start', Time32()),
        namedtype.NamedType('duration', Duration())
    )

class Time32(Uint32):
    pass

class Duration(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('microseconds', Uint16()),
        ('milliseconds', Uint16()),
        ('seconds', Uint16()),
        ('minutes', Uint16()),
        ('hours', Uint16()),
        ('sixtyHours', Uint16()),
        ('years', Uint16())
    )

class GeographicRegion(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('circularRegion', CircularRegion()),
        ('rectangularRegion', SequenceOfRectangularRegion()),
        ('polygonalRegion', PolygonalRegion()),
        ('identifiedRegion', SequenceOfIdentifiedRegion())
        # TODO more
    )

class CircularRegion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('center', TwoDLocation()),
        namedtype.NamedType('radius', Uint16())
    )

class TwoDLocation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('latitude', Latitude()),
        namedtype.NamedType('longitude', Longitude())
    )

class RectangularRegion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('northWest', TwoDLocation()),
        namedtype.NamedType('southEast', TwoDLocation())
    )

class PolygonalRegion(univ.SequenceOf):
    componentType = TwoDLocation()

class IdentifierdRegion(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('countryOnly', UnCountryId()),
        ('counrtyAndRegions', CountryAndRegions()),
        ('countryAndSubregions', CountryAndSubregions())
        # TODO more
    )

class UnCountryId(Uint16):
    pass

class CountryAndRegions(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('country', UnCountryId()),
        namedtype.NamedType('regions', SequenceOfUint8())
    )

class CountryAndSubregions(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('country', UnCountryId()),
        namedtype.NamedType('regionAndSubregions', SequenceOfRegionAndSubregions())
    )

class RegionAndSubregions(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('region', Uint8()),
        namedtype.NamedType('subregions', SequenceOfUint16())
    )

class SequenceOfRegionAndSubregions(univ.Sequence):
    componentType = RegionAndSubregions()

class SubjectAssurance(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(1, 1)

class PsidSsp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('psid', Psid()),
        namedtype.OptionalNamedType('ssp', ServiceSpecificPermissions())
    )

class SequenceOfPsidSsp(univ.SequenceOf):
    componentType = PsidSsp()

class ServiceSpecificPermissions(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('opaque', univ.OctetString()),
        ('bitmapSsp', BitmapSsp())
        # TODO more
    )

class BitmapSsp(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(0, 31)

class PsidGroupPermissions(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('subjectPermissions', SubjectPermissions()),
        namedtype.DefaultedNamedType('minChainLength', univ.Integer(1)),
        namedtype.DefaultedNamedType('chainLengthRange', univ.Integer(0)),
        namedtype.DefaultedNamedType('eeType', EndEntityType('app'))
    )

class SequenceOfPsidGroupPermissions(univ.SequenceOf):
    componentType = PsidGroupPermissions()

class SubjectPermissions(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('explicit', SequenceOfPsidSspRange()),
        ('all', univ.Null())
        # TODO more
    )

class EndEntityType(univ.BitString):
    namedValues = namedval.NamedValues(
        ('app', 0),
        ('enroll', 1)
    )
    subtypeSpec = constraint.ValueSizeConstraint(8, 8)

class PsidSspRange(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('psid', Psid()),
        namedtype.OptionalNamedType('sspRange', SspRange())
    )

class SequenceOfPsidSspRange(univ.SequenceOf):
    componentType = PsidSspRange()

class SspRange(univ.Choice):
    componentType = namedtype.NamedTypes(
        ('opaque', SequenceOfOctetString()),
        ('all', univ.Null()),
        ('bitmapSspRange', BitmapSspRange())
        # TODO more
    )

class BitmapSspRange(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('sspValue', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(1, 32))),
        namedtype.NamedType('sspBitmask', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(1, 32)))
    )

class SequenceOfAppExtensions(univ.SequenceOf):
    componentType = AppExtension()

class AppExtension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.ObjectIdentifier()),
        namedtype.NamedType('content', univ.Any())
    )

class SequenceOfCertIssueExtensions(univ.SequenceOf):
    componentType = CertIssueExtension()

class CertIssueExtension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('specific', univ.ObjectIdentifier()),
        namedtype.NamedType('permissions', univ.Choice(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('specific', univ.Any()),
                namedtype.NamedType('all', univ.Null())
            )
        ))
    )

class SequenceOfCertRequestExtensions(univ.SequenceOf):
    componentType = CertRequestExtension()

class CertRequestExtension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.ObjectIdentifier()),
        namedtype.NamedType('permissions', univ.Choice(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('specific', univ.Any()),
                namedtype.NamedType('all', univ.Null())
            )
        ))
    )

# class CERT-EXT-TYPE()

class OperatingOrganizationId(univ.ObjectIdentifier):
    pass

# class certExtId-OperatingOrganization ExtId

# class instanceOperatingOrganizationCertExtensions CERT-EXT-TYPE

# class SetCertExtensions CERT-EXT-TYPE

class VerificationKeyIndicator(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('verificationKey', PublicVerificationKey()),
        namedtype.NamedType('reconstructionValue', EccP256CurvePoint())
    )

class PublicVerificationKey(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ecdsaNistP256', EccP256CurvePoint()),
        namedtype.NamedType('ecdsaBrainpoolP256r1', EccP256CurvePoint()),
        namedtype.NamedType('ecdsaBrainpoolP384r1', EccP256CurvePoint()),
        namedtype.NamedType('ecdsaNistP384', EccP256CurvePoint()),
        namedtype.NamedType('ecsigSm2', EccP256CurvePoint()),
        # TODO more
    )

# --- 6.5 General Headerinfo extension ---
class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.ObjectIdentifier()),
        namedtype.NamedTypes('content', univ.Any())
    )

# class EXT-TYPE()

class ExtId(Uint8):
    pass

class Ieee1609ContributeHeaderInfoExtension(Extension):
    pass

class Ieee1609HeaderInfoExtensionId(ExtId):
    pass

# p2pcd8ByteLearningRequestId Ieee1609HeaderInfoExtensionId ::= 1

# --- 6.6 Contributed Headerinfo extension ---
class EtsiOriginatingHeaderInfoExtension(Extension):
    pass

# class EtsiTs103097HeaderInfoExtension EXT-TYPE()

# class EtsiTs102941CrlRequest ::= Null

# class etsiTs102941CrlRequestId ExtId ::= 1

# class EtsiTs102941DeltaCtlRequest ::= Null

# class etsiTs102941DeltaCtlRequestId ExtId ::= 2

# --- 7.3 CRL Verification Entity specification ---
class CRLContents(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Uint8()),
        namedtype.NamedType('crlSeries', CrlSeries()),
        namedtype.NamedType('crlCraca', HashedId8()),
        namedtype.NamedType('issueDate', Time32()),
        namedtype.NamedType('nextCrl', Time32()),
        namedtype.NamedType('priorityInfo', CrlPriorityInfo()),
        namedtype.NamedType('typeSpecific', TypeSpecificCrlContents())
    )

class TypeSpecificContents(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('fullHashCrl', ToBeSignedHashIdCrl()),
        namedtype.NamedType('deltaHashCrl', ToBeSignedHashIdCrl()),
        namedtype.NamedType('fullLinkedCrl', ToBeSignedLinkageValueCrl()),
        namedtype.NamedType('deltaLinkedCrl', ToBeSignedLinkageValueCrl()),
        namedtype.NamedType('fullLinkedCrlWithAlg', ToBeSignedLinkageValueCrlWithAlgIdentifier()),
        namedtype.NamedType('deltaLinkedCrlWithAlg', ToBeSignedLinkageValueCrlWithAlgIdentifier())
    )

class CrlPriorityInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('priority', Uint8())
        # TODO more
    )

class ToBeSignedHashIdCrl(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('crlSerials', Uint32()),
        namedtype.NamedType('entries', SequenceOfHashBasedRevocationInfo())
        # TODO more
    )

class HashBasedRevocationInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', HashedId10()),
        namedtype.NamedType('expiry', Time32())
        # TODO more
    )

class ToBeSignedLinkageValueCrl(univ.Sequence):
    componentType = namedtype.NamedType(
        namedtype.NamedType('iRev', IValue()),
        namedtype.NamedType('indexWithinI', Uint8()),
        namedtype.OptionalNamedType('individual', SequenceOfJMaxGroup()),
        namedtype.OptionalNamedType('groups', SequenceOfGroupCrlEntry()),
        namedtype.OptionalNamedType('groupSingleSeed', SequenceOfGroupSingleSeedCrlEntry())
        # TODO more
    )

class ToBeSignedLinkageValueCrlWithAlgIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('iRev', IValue()),
        namedtype.NamedType('indexWithinI', Uint8()),
        namedtype.OptionalNamedType('individual', SequenceOfJMaxGroup()),
        namedtype.OptionalNamedType('groups', SequenceOfGroupCrlEntry()),
        namedtype.OptionalNamedType('groupSingleSeed', SequenceOfGroupSingleSeedCrlEntry())
        # TODO more
    )

class JMaxGroup(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('jmax', Uint8()),
        namedtype.NamedType('contents', SequenceOfLAGroup())
        # TODO more
    )

class SequenceofJMaxGroup(univ.SequenceOf):
    componentType = JMaxGroup()

class LAGroup(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('la1Id', LaId()),
        namedtype.NamedType('la2Id', LaId()),
        namedtype.NamedType('contents', SequenceOfIMaxGroup())
        # TODO more
    )

class SequenceOfLAGroup(univ.SequenceOf):
    componentType = LAGroup()

class IMaxGroup(univ.Sequence):
    componentType = namedtype.NamedType(
        namedtype.NamedType('iMax', Uint16()),
        namedtype.NamedType('contents', SequenceOfIndividualRevocation()),
        namedtype.OptionalNamedType('singleSeed', SequenceOfLinkageSeed())
        # TODO more
    )

class SequenceOfIMaxGroup(univ.SequenceOf):
    componentType = IMaxGroup()

class IndividualRevocation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('linkageSeed1', LinkageSeed()),
        namedtype.NamedType('linkageSeed2', LinkageSeed())
        # TODO more
    )

class SequenceOfIndividualRevocation(univ.SequenceOf):
    componentType = IndividualRevocation()

class GroupCrlEntry(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('iMax', Uint16()),
        namedtype.NamedType('la1Id', LaId()),
        namedtype.NamedType('linkageSeed1', LinkageSeed()),
        namedtype.NamedType('la2Id', LaId()),
        namedtype.NamedType('linkageSeed2', LinkageSeed())
        # TODO more
    )

class SequenceOfGroupCrlEntry(univ.SequenceOf):
    componentType = GroupCrlEntry()

class LaId(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(2, 2)

class LinkageSeed(univ.OctetString): 
    subtypeSpec = constraint.ValueSizeConstraint(16, 16)

class SequenecofLinkageSeed(univ.SequenceOf):
    componentType = LinkageSeed()

class ExpansionAlgorithmIdentifier(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('sha256ForI-aesForJ', 0),
        ('sm3ForI-sm4ForJ', 1)
    )

class GroupSingleSeedCrlEntry(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('iMax', Uint16()),
        namedtype.NamedType('laId', LaId()),
        namedtype.NamedType('linkageSeed', LinkageSeed())
    )

class SequenceOfGroupSingleSeedCrlEntry(univ.SequenceOf):
    componentType = GroupSingleSeedCrlEntry()

class SeedEvolutionFunctionIdentifier(univ.Null):
    pass

class LvGenerationFunctionIdentifier(univ.Null):
    pass

# --- 7.4 CRL IEEE 1609.2 Security envelope ---



# --- 8.4 Datastructures ---
class Ieee1689dot2Peer2PeIDU(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Uint8()),
        namedtype.NamedType('content', univ.Choice(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('caCerts', CaCertP2pPDU())
                # TODO more
            )
        )
    ))

class CaCertP2pPDU(univ.SequenceOf):
    componentType = Certificate()