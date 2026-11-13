package io.mosip.certify.offer;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;

/**
 * {@code /offer} and {@code /offer/} answer the bundled page itself (static resources have no directory index, and a
 * forward under a servlet path other than {@code /} does not resolve). {@code /offer/demo-subjects} answers the example
 * subjects {@code certify.offer-page.demo-subjects} configures, which the page offers in place of a typed record id
 * (F-15).
 *
 * <p>The subjects come from the properties and from nothing else: the endpoint reads no data source and no holder
 * file, so it cannot enumerate a deployment's subjects, and an operator who configures none gets
 * {@code {"subjects":[]}}. The page is the only client (same origin, under the page's own security chain).
 * {@code no-store}, because a deployment's list is a restart away from changing and the page must not show a stale
 * one.</p>
 *
 * <p>{@code @EnableConfigurationProperties} here rather than only on {@link OfferPageSecurityConfiguration}: that chain
 * is absent under the {@code test} profile, and the controller needs the properties on any profile the page is on.</p>
 */
@RestController
@EnableConfigurationProperties(OfferPageProperties.class)
@ConditionalOnProperty(prefix = OfferPageProperties.PREFIX, name = "enabled", havingValue = "true")
public class OfferPageController {

    private static final ClassPathResource PAGE = new ClassPathResource("static/offer/index.html");

    private final OfferPageProperties properties;

    public OfferPageController(OfferPageProperties properties) {
        this.properties = properties;
    }

    @GetMapping(value = {"/offer", "/offer/"}, produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<byte[]> page() throws IOException {
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(PAGE.getContentAsByteArray());
    }

    @GetMapping(value = "/offer/demo-subjects", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<DemoSubjectsResponse> demoSubjects() {
        List<DemoSubjectsResponse.Subject> subjects = properties.demoSubjects().stream()
                .map(subject -> new DemoSubjectsResponse.Subject(subject.id(), subject.labelOrId(),
                        subject.credentialConfigurationIds()))
                .toList();
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(new DemoSubjectsResponse(subjects));
    }
}
