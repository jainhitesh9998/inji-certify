package io.mosip.certify.status;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves a Token Status List in the one format its row holds (draft-ietf-oauth-status-list section 8; owner decision
 * D-M11-2), under the {@code /credentials/**} paths the deployment already leaves open:
 * <ul>
 *     <li>{@code TokenStatusList} rows as {@code application/statuslist+jwt}, exactly as before;</li>
 *     <li>{@code TokenStatusListCwt} rows as {@code application/statuslist+cwt}, the raw COSE_Sign1_Tagged bytes
 *     (TSL section 8.2; ISO/IEC 18013-5 second edition 12.3.6.3).</li>
 * </ul>
 *
 * <p>The {@code Accept} header is disregarded: an {@code mso_mdoc} verifier reads CWT and no verifier needs JWT for one
 * (RFC 9110 section 12.5.1 lets a server disregard the header field), and answering 406 would break clients that send
 * {@code application/json} or nothing. The {@code Content-Type} is always the row's own.
 *
 * <p>The list is signed again when it is stale ({@link TokenStatusListService#served}); when an expired list cannot be
 * signed again now (the signer failed, failed within {@code renew-backoff}, or is still busy after {@code renew-wait})
 * the answer is 503 with {@code Retry-After}, never the expired list and never the MOSIP error envelope with 200. A CWT
 * list whose pinned signer expired is retired: 410 Gone without {@code Retry-After} once its own {@code exp} has passed
 * (D-M11-7).
 */
@Slf4j
@RestController
public class TokenStatusListController {

    private final TokenStatusListService lists;

    public TokenStatusListController(TokenStatusListService lists) {
        this.lists = lists;
    }

    @GetMapping(value = "/credentials/token-status-list/{id}")
    public ResponseEntity<byte[]> statusList(@PathVariable("id") String id) {
        try {
            return lists.served(id)
                    .map(served -> ResponseEntity.ok()
                            .header(HttpHeaders.CONTENT_TYPE, served.mediaType())
                            .body(served.body()))
                    .orElseGet(() -> ResponseEntity.notFound().build());
        } catch (TokenStatusListGoneException e) {
            // before the 503 mapping: a retired list's signer has expired, so asking again cannot help (D-M11-7)
            log.debug("Token status list {} is retired: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.GONE).build();
        } catch (TokenStatusListUnavailableException e) {
            // the service logged the signing failure with its stack trace once per back-off window
            log.debug("Token status list {} cannot be served: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .header(HttpHeaders.RETRY_AFTER, Long.toString(e.retryAfterSeconds())).build();
        }
    }
}
