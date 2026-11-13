package io.mosip.certify.status;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves a Token Status List as {@code application/statuslist+jwt} (draft-ietf-oauth-status-list section 8), under the
 * {@code /credentials/**} paths the deployment already leaves open. The list is signed again when it is stale
 * ({@link TokenStatusListService#jwt}); when an expired list cannot be signed again now (the signer failed, failed
 * within {@code renew-backoff}, or is still busy after {@code renew-wait}) the answer is 503 with {@code Retry-After},
 * never the expired list and never the MOSIP error envelope with 200.
 */
@Slf4j
@RestController
public class TokenStatusListController {

    private final TokenStatusListService lists;

    public TokenStatusListController(TokenStatusListService lists) {
        this.lists = lists;
    }

    @GetMapping(value = "/credentials/token-status-list/{id}", produces = {TokenStatusListService.MEDIA_TYPE, MediaType.TEXT_PLAIN_VALUE, MediaType.ALL_VALUE})
    public ResponseEntity<String> statusList(@PathVariable("id") String id) {
        try {
            return lists.jwt(id)
                    .map(jwt -> ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, TokenStatusListService.MEDIA_TYPE).body(jwt))
                    .orElseGet(() -> ResponseEntity.notFound().build());
        } catch (TokenStatusListUnavailableException e) {
            // the service logged the signing failure with its stack trace once per back-off window
            log.debug("Token status list {} cannot be served: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .header(HttpHeaders.RETRY_AFTER, Long.toString(e.retryAfterSeconds())).build();
        }
    }
}
