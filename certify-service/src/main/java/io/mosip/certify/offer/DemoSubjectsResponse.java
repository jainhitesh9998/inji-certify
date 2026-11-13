package io.mosip.certify.offer;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * The body of {@code GET /offer/demo-subjects} (F-15): the subjects {@link OfferPageProperties#demoSubjects()} lists,
 * and nothing else. Snake-case keys so the page reads the same names the property file writes
 * ({@code credential-configuration-ids}); {@code label} is always present, the id when the property sets none, so the
 * page never has to fall back itself.
 *
 * @param subjects the configured subjects, in configuration order; empty when the deployment configures none
 */
public record DemoSubjectsResponse(List<Subject> subjects) {

    /**
     * @param id                          the subject id the page sends as {@code request.subject}
     * @param label                       the display text (the configured label, else the id)
     * @param credentialConfigurationIds  empty: offered for every credential configuration
     */
    public record Subject(String id, String label,
                          @JsonProperty("credential_configuration_ids") List<String> credentialConfigurationIds) {
    }
}
