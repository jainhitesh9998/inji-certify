package io.mosip.certify.oid4vci.d13;

import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.deprecation.DeprecatedEndpoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 0.14.0 discovery: {@code GET /.well-known/openid-credential-issuer?version=latest|vd12|vd11} next to the current
 * document (which keeps answering when no {@code version} is given), and the {@code /issuance/.well-known/*} aliases
 * of that release. All deprecated from day one.
 */
@RestController
@ConditionalOnProperty(prefix = D13Properties.PREFIX, name = "enabled", havingValue = "true", matchIfMissing = true)
public class D13DiscoveryController {

    public static final String DEPRECATION_NAME = "oid4vci-d13-metadata";
    static final String REPLACEMENT = "/.well-known/openid-credential-issuer";

    private final D13MetadataService metadata;
    private final VCIssuanceService vcIssuanceService;

    public D13DiscoveryController(D13MetadataService metadata, VCIssuanceService vcIssuanceService) {
        this.metadata = metadata;
        this.vcIssuanceService = vcIssuanceService;
    }

    @DeprecatedEndpoint(name = DEPRECATION_NAME, since = D13CredentialController.SINCE, replacement = REPLACEMENT)
    @GetMapping(value = "/.well-known/openid-credential-issuer", params = "version")
    public ResponseEntity<Map<String, Object>> versionedMetadata(@RequestParam("version") String version) {
        return asJson(metadata.metadata(version));
    }

    @DeprecatedEndpoint(name = DEPRECATION_NAME, since = D13CredentialController.SINCE, replacement = REPLACEMENT)
    @GetMapping("/issuance/.well-known/openid-credential-issuer")
    public ResponseEntity<Map<String, Object>> issuanceMetadata(@RequestParam(name = "version", required = false, defaultValue = D13MetadataService.VERSION_LATEST) String version) {
        return asJson(metadata.metadata(version));
    }

    @DeprecatedEndpoint(name = DEPRECATION_NAME, since = D13CredentialController.SINCE, replacement = "/.well-known/did.json")
    @GetMapping(value = "/issuance/.well-known/did.json", produces = "application/json")
    public Map<String, Object> issuanceDidDocument() {
        return vcIssuanceService.getDIDDocument();
    }

    /**
     * The 0.14.0 credential issuer metadata is JSON only, and the {@code Content-Type} is set on the response rather
     * than declared with {@code produces}: a client that sends {@code Accept: application/jwt} or {@code text/html} gets
     * the document (OpenID4VCI 1.0 section 12.2.2 requires the media type to be named, and these deprecated aliases
     * serve the same unsigned form as the current path) instead of a 406, or a 500 from the {@code /issuance/} error
     * advice as {@code /issuance/.well-known/openid-credential-issuer} did. Bodies are unchanged, so the goldens replay.
     * The DID document beside it is not credential issuer metadata and keeps its mapping untouched.
     */
    private static ResponseEntity<Map<String, Object>> asJson(Map<String, Object> document) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(document);
    }
}
