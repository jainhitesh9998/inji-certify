package io.mosip.certify.keyprovider.keymanager;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.dto.CertificateDataResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.signature.dto.SignRequestDtoV2;
import io.mosip.kernel.signature.dto.SignResponseDto;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Mockito-backed keymanager that behaves like the real one where the provider depends on it: getAllCertificates
 * returns PEM certificates with the SHA-256 thumbprint (upper-case hex) as key id, and signv2 signs the base64url
 * payload with the alias's private key returning the JOSE-shaped signature (ECDSA concatenated) base64url encoded.
 */
final class KeymanagerStandIn {

    final KeymanagerService keymanagerService = mock(KeymanagerService.class);
    final SignatureServicev2 signatureService = mock(SignatureServicev2.class);
    private final JcaKeyProvider jca = new JcaKeyProvider("stand-in");
    private final Map<KeymanagerAlias, List<CertificateDataResponseDto>> certificates = new LinkedHashMap<>();
    private final Map<String, String> kidToJcaAlias = new LinkedHashMap<>();

    KeymanagerStandIn() {
        when(keymanagerService.getAllCertificates(anyString(), any())).thenAnswer(invocation -> {
            KeymanagerAlias alias = new KeymanagerAlias(invocation.getArgument(0), ((Optional<String>) invocation.getArgument(1)).orElse(""));
            List<CertificateDataResponseDto> list = certificates.getOrDefault(alias, List.of());
            return new AllCertificatesDataResponseDto(list.toArray(new CertificateDataResponseDto[0]));
        });
        when(signatureService.signv2(any(SignRequestDtoV2.class))).thenAnswer(invocation -> {
            SignRequestDtoV2 request = invocation.getArgument(0);
            KeymanagerAlias alias = new KeymanagerAlias(request.getApplicationId(), request.getReferenceId());
            // keymanager signs with the alias's current key: the latest-expiring one
            CertificateDataResponseDto current = certificates.get(alias).stream()
                    .max(java.util.Comparator.comparing(CertificateDataResponseDto::getExpiryAt)).orElseThrow();
            SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(request.getSignAlgorithm()).orElseThrow();
            byte[] data = Base64.getUrlDecoder().decode(request.getDataToSign());
            byte[] signature = jca.signRaw(data, jca.resolve(KeyRef.parse("stand-in:" + kidToJcaAlias.get(current.getKeyId()))), algorithm);
            String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
            return new SignResponseDto("base64url".equals(request.getResponseEncodingFormat()) ? encoded : "z" + encoded, LocalDateTime.now());
        });
    }

    /** Adds a certificate for the alias with the given validity window; returns its key id. */
    String addKey(KeymanagerAlias alias, SignatureAlgorithm algorithm, LocalDateTime issuedAt, LocalDateTime expiryAt) {
        String jcaAlias = alias + "#" + certificates.getOrDefault(alias, List.of()).size();
        X509Certificate certificate = jca.generate(jcaAlias, algorithm, "CN=" + alias, "vc-signing").chain().leaf().orElseThrow();
        String kid = thumbprint(certificate);
        kidToJcaAlias.put(kid, jcaAlias);
        certificates.computeIfAbsent(alias, k -> new ArrayList<>())
                .add(new CertificateDataResponseDto(pem(certificate), issuedAt, expiryAt, kid));
        return kid;
    }

    static String thumbprint(X509Certificate certificate) {
        try {
            return Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())).toUpperCase();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String pem(X509Certificate certificate) {
        try {
            return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static LocalDateTime at(String iso) {
        return LocalDateTime.ofInstant(java.time.Instant.parse(iso), ZoneOffset.UTC);
    }
}
