package io.mosip.certify.offer;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * {@code /offer} and {@code /offer/} answer the bundled page itself (static resources have no directory index, and a
 * forward under a servlet path other than {@code /} does not resolve).
 */
@RestController
@ConditionalOnProperty(prefix = OfferPageProperties.PREFIX, name = "enabled", havingValue = "true")
public class OfferPageController {

    private static final ClassPathResource PAGE = new ClassPathResource("static/offer/index.html");

    @GetMapping(value = {"/offer", "/offer/"}, produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<byte[]> page() throws IOException {
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(PAGE.getContentAsByteArray());
    }
}
