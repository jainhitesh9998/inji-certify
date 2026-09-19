package io.mosip.certify.status;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/** Serves a Token Status List as {@code application/statuslist+jwt} (draft-ietf-oauth-status-list section 8), under the {@code /credentials/**} paths the deployment already leaves open. */
@RestController
public class TokenStatusListController {

    private final TokenStatusListService lists;

    public TokenStatusListController(TokenStatusListService lists) {
        this.lists = lists;
    }

    @GetMapping(value = "/credentials/token-status-list/{id}", produces = {TokenStatusListService.MEDIA_TYPE, MediaType.TEXT_PLAIN_VALUE, MediaType.ALL_VALUE})
    public ResponseEntity<String> statusList(@PathVariable("id") String id) {
        return lists.jwt(id)
                .map(jwt -> ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, TokenStatusListService.MEDIA_TYPE).body(jwt))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
