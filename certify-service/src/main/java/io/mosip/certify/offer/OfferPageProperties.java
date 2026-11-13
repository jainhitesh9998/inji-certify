package io.mosip.certify.offer;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The credential offer page served at {@code {servletPath}/offer/}: a browser page that creates a pre-authorized
 * offer on this issuer, shows it as a QR code for a wallet, and can play the wallet itself. Off unless {@code enabled}
 * (the page is bundled either way; without the switch the security chain does not open its path).
 *
 * <p>{@code demo-subjects} is the list of example subjects the page offers in a dropdown instead of asking the visitor
 * to type a record id (F-15). It is written by the operator and served by {@link OfferPageController} as it is stored
 * here: nothing is ever derived from a data source, so a deployment that configures none enumerates nothing and the
 * page keeps its free-text field. An entry whose {@code credential-configuration-ids} is empty applies to every
 * credential configuration.</p>
 *
 * <p>Everything is checked at bind time, so a bad entry stops startup with a message naming it instead of showing a
 * wrong or unclickable option to a visitor. The label is display text only: it is written into the page with
 * {@code textContent}, never as HTML, so a label may contain {@code <} or {@code "}.</p>
 *
 * @param enabled       serve the page (and its dropdown) at {@code /offer/}
 * @param demoSubjects  the subjects the page offers, at most {@value #MAX_DEMO_SUBJECTS}; empty (the default) turns the
 *                      dropdown off
 */
@ConfigurationProperties(prefix = OfferPageProperties.PREFIX)
public record OfferPageProperties(@DefaultValue("false") boolean enabled,
                                  @DefaultValue List<DemoSubject> demoSubjects) {

    public static final String PREFIX = "certify.offer-page";
    /** More than a demo needs, and small enough to keep the page's dropdown usable. */
    public static final int MAX_DEMO_SUBJECTS = 50;
    /** The subject id is what the page sends as {@code request.subject}: the id characters plus {@code . _ : -}. */
    static final Pattern ID = Pattern.compile("[A-Za-z0-9._:-]+");
    static final int ID_MAX_LENGTH = 128;
    static final String ID_RULE = "letters, digits, '.', '_', ':' and '-', at most 128 characters (" + ID.pattern() + ")";
    static final int LABEL_MAX_LENGTH = 128;

    public OfferPageProperties {
        demoSubjects = demoSubjects == null ? List.of() : List.copyOf(demoSubjects);
        if (demoSubjects.size() > MAX_DEMO_SUBJECTS) {
            throw new IllegalArgumentException("certify.offer-page.demo-subjects lists " + demoSubjects.size()
                    + " subjects; at most " + MAX_DEMO_SUBJECTS + " are allowed");
        }
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < demoSubjects.size(); i++) {
            DemoSubject subject = demoSubjects.get(i);
            String entry = PREFIX + ".demo-subjects[" + i + "]";
            if (subject == null) {
                throw new IllegalArgumentException(entry + " is empty");
            }
            String id = subject.id();
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException(entry + ".id is required: it is the subject id the page sends as"
                        + " request.subject");
            }
            if (id.length() > ID_MAX_LENGTH) {
                throw new IllegalArgumentException(entry + ".id is " + id.length() + " characters long; at most "
                        + ID_MAX_LENGTH + " are allowed. The id must be " + ID_RULE);
            }
            if (!ID.matcher(id).matches()) {
                throw new IllegalArgumentException(entry + ".id '" + id + "' must be " + ID_RULE);
            }
            String label = subject.label();
            if (label != null && label.length() > LABEL_MAX_LENGTH) {
                throw new IllegalArgumentException(entry + ".label is " + label.length() + " characters long; at most "
                        + LABEL_MAX_LENGTH + " are allowed (it is shown next to the subject id in the page)");
            }
            if (!ids.add(id)) {
                throw new IllegalArgumentException(entry + ".id '" + id + "' repeats an earlier subject id; demo subject"
                        + " ids must be unique");
            }
        }
    }

    /**
     * One subject the page offers.
     *
     * @param id                        the value sent as {@code request.subject}: non-blank, at most 128 characters,
     *                                  matching {@code [A-Za-z0-9._:-]+}
     * @param label                     optional; the text shown in the dropdown, at most 128 characters. Unset or
     *                                  blank, the page shows the id. Display text only (read as text, not HTML)
     * @param credentialConfigurationIds optional; the credential configurations this subject can be issued for. Empty,
     *                                  it is offered for every configuration
     */
    public record DemoSubject(String id, String label, @DefaultValue List<String> credentialConfigurationIds) {

        public DemoSubject {
            List<String> configurations = new ArrayList<>();
            if (credentialConfigurationIds != null) {
                for (String configuration : credentialConfigurationIds) {
                    // an empty value (`credential-configuration-ids=`) means "every configuration", like no list at all
                    if (configuration != null && !configuration.isBlank()) {
                        configurations.add(configuration.trim());
                    }
                }
            }
            credentialConfigurationIds = List.copyOf(configurations);
        }

        /** The text the page shows for this subject: its label, else its id. */
        public String labelOrId() {
            return label == null || label.isBlank() ? id : label;
        }
    }
}
