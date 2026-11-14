package io.mosip.certify.status;

import com.nimbusds.jose.crypto.impl.ECDSA;
import io.mosip.certify.pki.CrlBuilder;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.Signer;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * The certificates the M-11c tests need, built here rather than embedded so each test can break exactly one rule: an
 * Annex B IACA (built by {@code certify-pki}, so the CRL builder accepts it; {@code pathLenConstraint} 0, so it issues
 * its signers directly), a multi-tier test root with {@code pathLenConstraint} 1 for the chains with an intermediate,
 * Document Signers and dedicated signers with chosen extended key usages, validity windows and issuers, and the CRLs
 * the policy reads.
 *
 * <p>Only the ECDSA signature of a built certificate is random; every test compares claims, headers and rules, never
 * certificate bytes.
 */
final class StatusListTestKeys {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    static final String CRL_URI = "https://issuer.example.test/v1/certify/mdoc/iaca/test-iaca.crl";

    /** The IACA's own validity start: far enough back that a stale CRL can lie before it. */
    static final Instant LONG_AGO = Instant.now().minus(200, ChronoUnit.DAYS);

    static final KeyPair IACA_KEYS = p256();
    static final X509Certificate IACA = IsoMdocProfiles.iaca(IACA_KEYS).country("IN").organization("Lorem Ipsum Demo")
            .commonName("Status List Test IACA").issuerAltUri("https://issuer.example.test")
            .crlDistributionPoint(CRL_URI).notBefore(LONG_AGO).build();

    /** A second IACA-shaped certificate no anchor names, and its signer: what keymanager's master-signed key looks like. */
    static final KeyPair OTHER_CA_KEYS = p256();
    static final X509Certificate OTHER_CA = IsoMdocProfiles.iaca(OTHER_CA_KEYS).country("IN")
            .commonName("Status List Other Test CA").issuerAltUri("https://other.example.test")
            .crlDistributionPoint("https://other.example.test/iaca.crl").notBefore(LONG_AGO).build();

    /** The Document Signer that signs the mDLs, and therefore their status list (D-M11-1 (a)). */
    static final KeyPair DSC_KEYS = p256();
    static final X509Certificate DSC = signer(DSC_KEYS, "Status List Test DSC", IACA, IACA_KEYS,
            List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().plus(200, ChronoUnit.DAYS));

    /** A signer the IACA delegated status-list signing to (TSL section 10, IANA value 45). */
    static final KeyPair DEDICATED_KEYS = p256();
    static final X509Certificate DEDICATED = signer(DEDICATED_KEYS, "Status List Test Dedicated Signer", IACA, IACA_KEYS,
            List.of(StatusListSignerPolicy.STATUS_SIGNING_EKU), true, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().plus(200, ChronoUnit.DAYS));

    /** Issued by the IACA, no extended key usage at all. */
    static final KeyPair NO_EKU_KEYS = p256();
    static final X509Certificate NO_EKU = signer(NO_EKU_KEYS, "Status List Test No EKU", IACA, IACA_KEYS, List.of(),
            true, LONG_AGO.plus(100, ChronoUnit.DAYS), Instant.now().plus(200, ChronoUnit.DAYS));

    /** Issued by the IACA with the Document Signer EKU but without {@code digitalSignature}. */
    static final KeyPair NO_DIGITAL_SIGNATURE_KEYS = p256();
    static final X509Certificate NO_DIGITAL_SIGNATURE = signer(NO_DIGITAL_SIGNATURE_KEYS,
            "Status List Test Encipherment Only", IACA, IACA_KEYS, List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU),
            false, LONG_AGO.plus(100, ChronoUnit.DAYS), Instant.now().plus(200, ChronoUnit.DAYS));

    /** A Document Signer- shaped certificate no configured IACA issued (keymanager's case once IACAs are configured). */
    static final KeyPair UNTRUSTED_KEYS = p256();
    static final X509Certificate UNTRUSTED = signer(UNTRUSTED_KEYS, "Status List Test Untrusted DSC", OTHER_CA,
            OTHER_CA_KEYS, List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true,
            LONG_AGO.plus(100, ChronoUnit.DAYS), Instant.now().plus(200, ChronoUnit.DAYS));

    /** A Document Signer the IACA issued whose validity already ended. */
    static final KeyPair EXPIRED_KEYS = p256();
    static final X509Certificate EXPIRED = signer(EXPIRED_KEYS, "Status List Test Expired DSC", IACA, IACA_KEYS,
            List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().minus(1, ChronoUnit.DAYS));

    /** A Document Signer the IACA issued whose validity has not begun. */
    static final KeyPair NOT_YET_VALID_KEYS = p256();
    static final X509Certificate NOT_YET_VALID = signer(NOT_YET_VALID_KEYS, "Status List Test Future DSC", IACA,
            IACA_KEYS, List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true,
            Instant.now().plus(1, ChronoUnit.DAYS), Instant.now().plus(200, ChronoUnit.DAYS));

    /**
     * A self-signed test root with {@code pathLenConstraint} 1, standing in for an anchor that allows one intermediate.
     * An Annex B IACA carries 0 (AnnexBValidator {@code IACA_PATHLEN}), so the intermediate chains that must pass live
     * under this root, not under {@link #IACA}; {@link #rootCrl} is its CRL.
     */
    static final KeyPair MULTI_TIER_ROOT_KEYS = p256();
    static final X509Certificate MULTI_TIER_ROOT = root(MULTI_TIER_ROOT_KEYS, "Status List Test Multi-Tier Root", 1,
            LONG_AGO, Instant.now().plus(300, ChronoUnit.DAYS));

    /** A CA intermediate between the multi-tier root and a Document Signer: cA TRUE, keyCertSign, no pathLen limit. */
    static final KeyPair INTERMEDIATE_KEYS = p256();
    static final X509Certificate INTERMEDIATE = ca(INTERMEDIATE_KEYS, "Status List Test Intermediate", MULTI_TIER_ROOT,
            MULTI_TIER_ROOT_KEYS, null, LONG_AGO.plus(100, ChronoUnit.DAYS), Instant.now().plus(200, ChronoUnit.DAYS));

    static final KeyPair BEHIND_INTERMEDIATE_KEYS = p256();
    static final X509Certificate BEHIND_INTERMEDIATE = signer(BEHIND_INTERMEDIATE_KEYS,
            "Status List Test Intermediate DSC", INTERMEDIATE, INTERMEDIATE_KEYS,
            List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().plus(200, ChronoUnit.DAYS));

    /** A second CA below {@link #INTERMEDIATE}: two intermediates, one more than the multi-tier root allows. */
    static final KeyPair DEEP_INTERMEDIATE_KEYS = p256();
    static final X509Certificate DEEP_INTERMEDIATE = ca(DEEP_INTERMEDIATE_KEYS, "Status List Test Deep Intermediate",
            INTERMEDIATE, INTERMEDIATE_KEYS, null, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().plus(200, ChronoUnit.DAYS));
    static final KeyPair BEHIND_DEEP_INTERMEDIATE_KEYS = p256();
    static final X509Certificate BEHIND_DEEP_INTERMEDIATE = signer(BEHIND_DEEP_INTERMEDIATE_KEYS,
            "Status List Test Deep Intermediate DSC", DEEP_INTERMEDIATE, DEEP_INTERMEDIATE_KEYS,
            List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().plus(200, ChronoUnit.DAYS));

    /**
     * A CA intermediate the Annex B {@link #IACA} ({@code pathLenConstraint} 0) issued, and a Document Signer below it:
     * the path Annex B forbids, which Multipaz and OpenSSL refuse ("path length exceeded").
     */
    static final KeyPair IACA_INTERMEDIATE_KEYS = p256();
    static final X509Certificate IACA_INTERMEDIATE = ca(IACA_INTERMEDIATE_KEYS, "Status List Test IACA Intermediate",
            IACA, IACA_KEYS, null, LONG_AGO.plus(100, ChronoUnit.DAYS), Instant.now().plus(200, ChronoUnit.DAYS));
    static final KeyPair BEHIND_IACA_INTERMEDIATE_KEYS = p256();
    static final X509Certificate BEHIND_IACA_INTERMEDIATE = signer(BEHIND_IACA_INTERMEDIATE_KEYS,
            "Status List Test Behind An IACA Intermediate", IACA_INTERMEDIATE, IACA_INTERMEDIATE_KEYS,
            List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().plus(200, ChronoUnit.DAYS));

    /** A CA intermediate that expires ten days from now, long before the signer below it. */
    static final KeyPair SHORT_INTERMEDIATE_KEYS = p256();
    static final X509Certificate SHORT_INTERMEDIATE = ca(SHORT_INTERMEDIATE_KEYS, "Status List Test Short Intermediate",
            MULTI_TIER_ROOT, MULTI_TIER_ROOT_KEYS, null, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().plus(10, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS));
    static final KeyPair BEHIND_SHORT_INTERMEDIATE_KEYS = p256();
    static final X509Certificate BEHIND_SHORT_INTERMEDIATE = signer(BEHIND_SHORT_INTERMEDIATE_KEYS,
            "Status List Test Behind A Short Intermediate", SHORT_INTERMEDIATE, SHORT_INTERMEDIATE_KEYS,
            List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().plus(200, ChronoUnit.DAYS));

    /** An IACA that expires ten days from now, and a signer it issued that outlives it (the anchor ends first). */
    static final KeyPair SHORT_IACA_KEYS = p256();
    static final X509Certificate SHORT_IACA = IsoMdocProfiles.iaca(SHORT_IACA_KEYS).country("IN")
            .commonName("Status List Test Short IACA").issuerAltUri("https://short.example.test")
            .crlDistributionPoint("https://short.example.test/iaca.crl").notBefore(LONG_AGO)
            .validity(Duration.between(LONG_AGO.truncatedTo(ChronoUnit.SECONDS),
                    Instant.now().plus(10, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS)))
            .build();
    static final KeyPair UNDER_SHORT_IACA_KEYS = p256();
    static final X509Certificate UNDER_SHORT_IACA = signer(UNDER_SHORT_IACA_KEYS, "Status List Test Under A Short IACA",
            SHORT_IACA, SHORT_IACA_KEYS, List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true,
            LONG_AGO.plus(100, ChronoUnit.DAYS), Instant.now().plus(100, ChronoUnit.DAYS));

    /**
     * A self-issued key-rollover intermediate (subject and issuer names equal, signed by another key), the shape
     * {@code CertificateChain.withoutAnchor()} counts as self-signed: with the IACA dropped, the token's x5chain would
     * carry it.
     */
    static final KeyPair ROLLOVER_KEYS = p256();
    static final X509Certificate ROLLOVER = rolloverIntermediate(ROLLOVER_KEYS);
    static final KeyPair ROLLOVER_DSC_KEYS = p256();
    static final X509Certificate ROLLOVER_DSC = signer(ROLLOVER_DSC_KEYS, "Status List Rollover", ROLLOVER,
            ROLLOVER_KEYS, List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true,
            LONG_AGO.plus(100, ChronoUnit.DAYS), Instant.now().plus(200, ChronoUnit.DAYS));

    /**
     * An end-entity certificate (no basicConstraints, only {@code digitalSignature}) that signs another certificate: the
     * shape a signature-only chain check would accept as an intermediate.
     */
    static final KeyPair END_ENTITY_INTERMEDIATE_KEYS = p256();
    static final X509Certificate END_ENTITY_INTERMEDIATE = signer(END_ENTITY_INTERMEDIATE_KEYS,
            "Status List Test End Entity Intermediate", IACA, IACA_KEYS, List.of(), true,
            LONG_AGO.plus(100, ChronoUnit.DAYS), Instant.now().plus(200, ChronoUnit.DAYS));
    static final KeyPair BEHIND_END_ENTITY_INTERMEDIATE_KEYS = p256();
    static final X509Certificate BEHIND_END_ENTITY_INTERMEDIATE = signer(BEHIND_END_ENTITY_INTERMEDIATE_KEYS,
            "Status List Test Behind An End Entity", END_ENTITY_INTERMEDIATE, END_ENTITY_INTERMEDIATE_KEYS,
            List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().plus(200, ChronoUnit.DAYS));

    /**
     * An intermediate CA with {@code pathLenConstraint} 0 and a CA intermediate below it: RFC 5280 section 6.1.4 forbids
     * that whatever the anchor allows.
     */
    static final KeyPair PATHLEN_ZERO_KEYS = p256();
    static final X509Certificate PATHLEN_ZERO = ca(PATHLEN_ZERO_KEYS, "Status List Test PathLen Zero CA", MULTI_TIER_ROOT,
            MULTI_TIER_ROOT_KEYS, 0, LONG_AGO.plus(100, ChronoUnit.DAYS), Instant.now().plus(200, ChronoUnit.DAYS));
    static final KeyPair SUB_INTERMEDIATE_KEYS = p256();
    static final X509Certificate SUB_INTERMEDIATE = ca(SUB_INTERMEDIATE_KEYS, "Status List Test Sub Intermediate",
            PATHLEN_ZERO, PATHLEN_ZERO_KEYS, null, LONG_AGO.plus(100, ChronoUnit.DAYS), Instant.now().plus(200, ChronoUnit.DAYS));
    static final KeyPair SUB_INTERMEDIATE_DSC_KEYS = p256();
    static final X509Certificate SUB_INTERMEDIATE_DSC = signer(SUB_INTERMEDIATE_DSC_KEYS,
            "Status List Test Sub Intermediate DSC", SUB_INTERMEDIATE, SUB_INTERMEDIATE_KEYS,
            List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true, LONG_AGO.plus(100, ChronoUnit.DAYS),
            Instant.now().plus(200, ChronoUnit.DAYS));

    /** An IACA whose validity ended long ago, and a signer it issued that is valid now (only the anchor's dates are odd). */
    static final KeyPair EXPIRED_IACA_KEYS = p256();
    static final X509Certificate EXPIRED_IACA = IsoMdocProfiles.iaca(EXPIRED_IACA_KEYS).country("IN")
            .commonName("Status List Test Expired IACA").issuerAltUri("https://expired.example.test")
            .crlDistributionPoint("https://expired.example.test/iaca.crl")
            .notBefore(Instant.now().minus(400, ChronoUnit.DAYS)).validity(Duration.ofDays(100)).build();
    static final KeyPair UNDER_EXPIRED_IACA_KEYS = p256();
    static final X509Certificate UNDER_EXPIRED_IACA = signer(UNDER_EXPIRED_IACA_KEYS,
            "Status List Test Under An Expired IACA", EXPIRED_IACA, EXPIRED_IACA_KEYS,
            List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true, Instant.now().minus(50, ChronoUnit.DAYS),
            Instant.now().plus(100, ChronoUnit.DAYS));

    /**
     * {@link #EXPIRED_IACA} re-issued with the same name and key, valid now and ending before the signer it issued
     * ({@link #UNDER_EXPIRED_IACA}), so a cap at its {@code notAfter} is visible (G45, M-11d review round 4).
     */
    static final X509Certificate REISSUED_IACA = IsoMdocProfiles.iaca(EXPIRED_IACA_KEYS).country("IN")
            .commonName("Status List Test Expired IACA").issuerAltUri("https://expired.example.test")
            .crlDistributionPoint("https://expired.example.test/iaca.crl")
            .notBefore(Instant.now().minus(60, ChronoUnit.DAYS)).validity(Duration.ofDays(110)).build();
    /** The same IACA re-issued again ahead of time: not yet valid, and ending after every other one. */
    static final X509Certificate STAGED_IACA = IsoMdocProfiles.iaca(EXPIRED_IACA_KEYS).country("IN")
            .commonName("Status List Test Expired IACA").issuerAltUri("https://expired.example.test")
            .crlDistributionPoint("https://expired.example.test/iaca.crl")
            .notBefore(Instant.now().plus(30, ChronoUnit.DAYS)).validity(Duration.ofDays(400)).build();

    /** An IACA that is not yet valid, and a signer it issued that is valid now. */
    static final KeyPair FUTURE_IACA_KEYS = p256();
    static final X509Certificate FUTURE_IACA = IsoMdocProfiles.iaca(FUTURE_IACA_KEYS).country("IN")
            .commonName("Status List Test Future IACA").issuerAltUri("https://future.example.test")
            .crlDistributionPoint("https://future.example.test/iaca.crl")
            .notBefore(Instant.now().plus(10, ChronoUnit.DAYS)).validity(Duration.ofDays(300)).build();
    static final KeyPair UNDER_FUTURE_IACA_KEYS = p256();
    static final X509Certificate UNDER_FUTURE_IACA = signer(UNDER_FUTURE_IACA_KEYS,
            "Status List Test Under A Future IACA", FUTURE_IACA, FUTURE_IACA_KEYS,
            List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true, Instant.now().minus(1, ChronoUnit.DAYS),
            Instant.now().plus(100, ChronoUnit.DAYS));

    private StatusListTestKeys() {}

    static KeyPair p256() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static X509Certificate signer(KeyPair subject, String commonName, X509Certificate issuer, KeyPair issuerKeys,
                                  List<String> extendedKeyUsage, boolean digitalSignature, Instant notBefore,
                                  Instant notAfter) {
        return issue(subject, new X500Name("CN=" + commonName), issuer, issuerKeys, extendedKeyUsage,
                digitalSignature, notBefore, notAfter, false, null);
    }

    /** A CA certificate: {@code basicConstraints cA TRUE} (with {@code pathLen} when given) and key usage keyCertSign. */
    static X509Certificate ca(KeyPair subject, String commonName, X509Certificate issuer, KeyPair issuerKeys,
                              Integer pathLen, Instant notBefore, Instant notAfter) {
        return issue(subject, new X500Name("CN=" + commonName), issuer, issuerKeys, List.of(), true, notBefore,
                notAfter, true, pathLen);
    }

    /** A self-signed CA: {@code basicConstraints cA TRUE, pathLenConstraint} as given (critical), keyCertSign and cRLSign. */
    static X509Certificate root(KeyPair keys, String commonName, int pathLen, Instant notBefore, Instant notAfter) {
        try {
            X500Name name = new X500Name("CN=" + commonName);
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serial(), Date.from(notBefore),
                    Date.from(notAfter), name, keys.getPublic());
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keys.getPublic()));
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            return new JcaX509CertificateConverter().getCertificate(builder.build(
                    new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(keys.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The key-rollover intermediate: its subject and issuer names are equal, so the chain library calls it self-signed. */
    private static X509Certificate rolloverIntermediate(KeyPair keys) {
        try {
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    X500Name.getInstance(IACA.getSubjectX500Principal().getEncoded()), serial(),
                    Date.from(LONG_AGO.plus(100, ChronoUnit.DAYS)), Date.from(Instant.now().plus(200, ChronoUnit.DAYS)),
                    X500Name.getInstance(IACA.getSubjectX500Principal().getEncoded()), keys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
            return new JcaX509CertificateConverter().getCertificate(builder.build(
                    new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(IACA_KEYS.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate issue(KeyPair subject, X500Name subjectName, X509Certificate issuer, KeyPair issuerKeys,
                                         List<String> extendedKeyUsage, boolean digitalSignature, Instant notBefore,
                                         Instant notAfter, boolean ca, Integer pathLen) {
        try {
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()), serial(),
                    Date.from(notBefore), Date.from(notAfter), subjectName, subject.getPublic());
            JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    extensions.createAuthorityKeyIdentifier(issuer.getPublicKey()));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extensions.createSubjectKeyIdentifier(subject.getPublic()));
            if (ca) {
                builder.addExtension(Extension.basicConstraints, true,
                        pathLen == null ? new BasicConstraints(true) : new BasicConstraints(pathLen));
                builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            } else {
                builder.addExtension(Extension.keyUsage, true, new KeyUsage(digitalSignature
                        ? KeyUsage.digitalSignature : KeyUsage.keyEncipherment));
            }
            if (!extendedKeyUsage.isEmpty()) {
                builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
                        extendedKeyUsage.stream().map(oid -> KeyPurposeId.getInstance(new ASN1ObjectIdentifier(oid)))
                                .toArray(KeyPurposeId[]::new)));
            }
            return new JcaX509CertificateConverter().getCertificate(builder.build(
                    new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(issuerKeys.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static BigInteger serial() {
        return new BigInteger(72, new java.security.SecureRandom()).setBit(71);
    }

    /** A CRL of the test IACA: {@code thisUpdate}/{@code nextUpdate} as given, revoking {@code serials}. */
    static X509CRL crl(Instant thisUpdate, Instant nextUpdate, BigInteger... serials) {
        CrlBuilder builder = CrlBuilder.forIaca(IACA, IACA_KEYS).crlNumber(BigInteger.ONE)
                .thisUpdate(thisUpdate).nextUpdate(nextUpdate);
        for (BigInteger serial : serials) {
            builder.revoke(serial, thisUpdate);
        }
        return builder.build();
    }

    /**
     * A CRL of {@link #MULTI_TIER_ROOT} revoking {@code serials}: built with Bouncy Castle directly, because
     * {@code CrlBuilder.forIaca} accepts only an Annex B IACA ({@code pathLenConstraint} 0).
     */
    static X509CRL rootCrl(Instant thisUpdate, Instant nextUpdate, BigInteger... serials) {
        try {
            X509v2CRLBuilder builder = new X509v2CRLBuilder(
                    X500Name.getInstance(MULTI_TIER_ROOT.getSubjectX500Principal().getEncoded()), Date.from(thisUpdate));
            builder.setNextUpdate(Date.from(nextUpdate));
            builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(MULTI_TIER_ROOT.getPublicKey()));
            for (BigInteger serial : serials) {
                builder.addCRLEntry(serial, Date.from(thisUpdate), CRLReason.unspecified);
            }
            return new JcaX509CRLConverter().getCRL(builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(MULTI_TIER_ROOT_KEYS.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A CRL of the test IACA that does not list {@link #DSC} and is fresh at {@code now}. */
    static X509CRL freshCrl() {
        return crl(Instant.now().minus(1, ChronoUnit.HOURS), Instant.now().plus(20, ChronoUnit.DAYS));
    }

    /** A CRL of the test IACA whose {@code nextUpdate} passed a hundred days ago: stale at {@code now}. */
    static X509CRL staleCrl() {
        return crl(Instant.now().minus(200, ChronoUnit.DAYS), Instant.now().minus(100, ChronoUnit.DAYS));
    }

    /** A signing context over a key and chain, without going through a provider (expired DSCs never resolve there). */
    static SigningContext context(KeyPair keys, CertificateChain chain) {
        KeyRef ref = new KeyRef("jca", "status-list-test");
        PublicKeyDescriptor descriptor = new PublicKeyDescriptor("status-list-test", SignatureAlgorithm.ES256,
                keys.getPublic(), chain, null, null, "mdoc-dsc");
        return new SigningContext(SigningConfig.of(ref, SignatureAlgorithm.ES256),
                new SigningKey(ref, descriptor, keys.getPrivate()), SIGNER);
    }

    static SigningContext context(KeyPair keys, X509Certificate... certificates) {
        return context(keys, CertificateChain.of(certificates));
    }

    /** Signs through plain JCA with the context's key, in the R||S wire form a key provider returns. */
    static final class JcaSigner implements Signer {

        @Override
        public byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm) {
            try {
                Signature signature = Signature.getInstance(algorithm.jcaName());
                signature.initSign((PrivateKey) key.providerHandle());
                signature.update(data);
                return ECDSA.transcodeSignatureToConcat(signature.sign(), algorithm.concatLength());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    static final Signer SIGNER = new JcaSigner();

    /**
     * A provider whose one key a test can swap, standing in for keymanager rotating a key under one reference: the
     * {@code kid} is a thumbprint, not the alias, so {@code pin} keeps the configured reference.
     */
    static final class MutableProvider implements KeyProvider {

        private final String id;
        private SigningKey key;

        MutableProvider(String id, SigningKey key) {
            this.id = id;
            this.key = key;
        }

        void holds(SigningKey replacement) {
            this.key = replacement;
        }

        @Override
        public String id() {
            return id;
        }

        @Override
        public SigningKey resolve(KeyRef ref) {
            return new SigningKey(ref, key.descriptor(), key.providerHandle());
        }

        @Override
        public List<PublicKeyDescriptor> publicKeys(KeyFilter filter) {
            return List.of(key.descriptor());
        }

        @Override
        public Set<SignatureAlgorithm> supportedAlgorithms() {
            return Set.of(SignatureAlgorithm.ES256);
        }

        @Override
        public byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm) {
            return SIGNER.signRaw(data, key, algorithm);
        }
    }

    /** A key as a provider would report it: some {@code kid}, a chain and the private handle. */
    static SigningKey key(String kid, KeyPair keys, X509Certificate... chain) {
        KeyRef ref = new KeyRef("jca", kid);
        return new SigningKey(ref, new PublicKeyDescriptor(kid, SignatureAlgorithm.ES256, keys.getPublic(),
                CertificateChain.of(chain), null, null, "mdoc-dsc"), keys.getPrivate());
    }
}
