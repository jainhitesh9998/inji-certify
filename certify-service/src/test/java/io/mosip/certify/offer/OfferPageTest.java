package io.mosip.certify.offer;

import io.mosip.certify.api.spi.DataProviderPlugin;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The offer page and its QR library are bundled and served under the servlet path; {@code /offer/} forwards to the page.
 * The page also offers the subjects {@code certify.offer-page.demo-subjects} configures (F-15) instead of asking the
 * visitor to type a record id.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "certify.offer-page.enabled=true",
        // the demo wiring of config/certify-mdl.properties, plus the two shapes the page falls back on: a subject with
        // no label (the id is shown) and one for a single configuration, whose label is display text only
        "certify.offer-page.demo-subjects[0].id=mdl-demo-1",
        "certify.offer-page.demo-subjects[0].label=Asha Demo",
        "certify.offer-page.demo-subjects[0].credential-configuration-ids[0]=org.iso.18013.5.1.mDL",
        "certify.offer-page.demo-subjects[1].id=mdl-demo-2",
        "certify.offer-page.demo-subjects[2].id=farmer-1",
        "certify.offer-page.demo-subjects[2].label=<b>Bold \"quoted\" <script>alert(1)</script></b>",
        "certify.offer-page.demo-subjects[2].credential-configuration-ids=FarmerCredential"
})
class OfferPageTest {

    @Autowired MockMvc mockMvc;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @Test
    void thePageAndItsScriptAreServed() throws Exception {
        MvcResult page = mockMvc.perform(get("/offer/index.html")).andReturn();
        assertEquals(200, page.getResponse().getStatus());
        String html = page.getResponse().getContentAsString();
        assertTrue(html.contains("<title>Credential offer</title>") && html.contains("/pre-authorized-data") && html.contains("openid4vci-proof+jwt"), "the page creates offers and plays the wallet");
        // M-09/F-18: the page can target either surface for every format except mso_mdoc, which the compatibility
        // endpoint cannot issue (D5: its legacy option is disabled and the surface forced to /oid4vci), and reads an
        // IssuerSigned it is handed; the IACA it verifies against is published next to it. The behaviour is asserted by
        // docs/design/tools/check-offer-page.mjs (CI step "Offer page behaviour (node)")
        assertTrue(html.contains("id=\"surface\"") && html.contains("offer_by_value"), "the page offers the surface selector and by-value offers");
        assertTrue(html.contains("id=\"surfaceLegacy\"") && html.contains("el(\"surfaceLegacy\").disabled = mdoc;"),
                "an mso_mdoc configuration cannot be offered on the compatibility surface");
        assertTrue(html.contains("Cbor.decode") && html.contains("../mdoc/iaca"), "the page decodes mso_mdoc and links the IACA");
        // F-18: the in-page wallet is offered for every published offer, on either surface, and redeems it where the offer
        // issuer's own metadata says once that metadata's identity is checked (whether a compatibility-surface offer then
        // verifies depends on the deployment's identity configuration, gap G34); a replaced portrait releases its blob URL
        assertTrue(html.contains("el(\"wallet\").disabled = !grant;"), "the wallet is offered for either surface");
        assertTrue(html.contains("portraitObjectUrls.forEach((url) => URL.revokeObjectURL(url))"), "a replaced portrait's object URL is revoked");
        MvcResult script = mockMvc.perform(get("/offer/qrcode.min.js")).andReturn();
        assertEquals(200, script.getResponse().getStatus());
        assertTrue(script.getResponse().getContentAsString().startsWith("var QRCode;"));
        MvcResult cbor = mockMvc.perform(get("/offer/cbor.js")).andReturn();
        assertEquals(200, cbor.getResponse().getStatus());
        assertTrue(cbor.getResponse().getContentAsString().contains("var Cbor"), "the CBOR decoder is bundled, not fetched from a CDN");
        MvcResult directory = mockMvc.perform(get("/offer/")).andReturn();
        assertEquals(200, directory.getResponse().getStatus());
        assertTrue(directory.getResponse().getContentType().startsWith("text/html") && directory.getResponse().getContentAsString().equals(html), "the directory path answers the same page");
    }

    @Test
    void thePageOffersTheConfiguredDemoSubjectsAndFetchesThem() throws Exception {
        String html = mockMvc.perform(get("/offer/")).andReturn().getResponse().getContentAsString();
        assertTrue(html.contains("<select id=\"subjectChoice\" hidden></select>"), "the dropdown starts hidden and above the typed field");
        assertTrue(html.indexOf("id=\"subjectChoice\"") < html.indexOf("id=\"subject\""), "the dropdown is above the typed subject input");
        assertTrue(html.contains("Other (type a subject id)"), "a visitor can still type a subject id");
        assertTrue(html.contains("/offer/demo-subjects") && html.contains("api(\"GET\", DEMO_SUBJECTS)"), "the page fetches the configured subjects on load");
        assertTrue(html.contains("refreshSubjectChoice") && html.contains("subjectsFor(demoSubjects, el(\"configuration\").value)"),
                "the options are re-filtered on a configuration change");
        // the claims field keeps working: with "Other" and an empty subject the claims are used, and the label says so
        // while the dropdown is on screen
        assertTrue(html.contains("const subject = chosenSubject();") && html.contains("else if (el(\"claims\").value.trim())"),
                "an empty subject still falls through to the claims JSON");
        assertTrue(html.contains("id=\"claimsLabel\"") && html.contains("CLAIMS_HINT_WITH_CHOICE"),
                "the claims label explains when the claims apply");
    }

    @Test
    void subjectLabelsAreTextAndNeverMarkup() throws Exception {
        String html = mockMvc.perform(get("/offer/")).andReturn().getResponse().getContentAsString();
        assertTrue(html.contains("option.textContent = subject.label && subject.label !== subject.id ? subject.label + \" (\" + subject.id + \")\" : subject.id;"),
                "a subject label is assigned with textContent, so a label containing < or \" stays text; a label that only repeats the id (or is empty) is printed once (F-18)");
        assertTrue(html.contains("option.value = subject.id;"), "the id is an option value, never markup");
        // every innerHTML assignment in the page clears a container of the page's own making; none takes server data.
        // The count is deliberately not asserted: what matters is that no assignment carries a value.
        Matcher assignments = Pattern.compile("innerHTML\\s*=\\s*([^;]*);").matcher(html);
        while (assignments.find()) {
            assertEquals("\"\"", assignments.group(1).trim(),
                    "innerHTML is only ever cleared, never fed a server value: " + assignments.group());
        }
        // the subject labels are toggled with `hidden`, and the page's own `label { display: block }` beats the UA's
        // [hidden] rule: without this the labels of the page's demo-subject controls are always visible
        assertTrue(Pattern.compile("\\[hidden\\]\\s*\\{[^}]*display:\\s*none\\s*!important").matcher(html).find(),
                "the stylesheet makes [hidden] win over label { display: block }");
    }

    @Test
    void theEndpointAnswersTheConfiguredSubjects() throws Exception {
        MvcResult answer = mockMvc.perform(get("/offer/demo-subjects"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.subjects", hasSize(3)))
                .andExpect(jsonPath("$.subjects[0].id").value("mdl-demo-1"))
                .andExpect(jsonPath("$.subjects[0].label").value("Asha Demo"))
                .andExpect(jsonPath("$.subjects[0].credential_configuration_ids[0]").value("org.iso.18013.5.1.mDL"))
                // no label configured: the id is the label, so the page never has to fall back itself
                .andExpect(jsonPath("$.subjects[1].id").value("mdl-demo-2"))
                .andExpect(jsonPath("$.subjects[1].label").value("mdl-demo-2"))
                .andExpect(jsonPath("$.subjects[1].credential_configuration_ids", hasSize(0)))
                // allowed by the configuration, served verbatim: the page assigns it with textContent
                .andExpect(jsonPath("$.subjects[2].label").value("<b>Bold \"quoted\" <script>alert(1)</script></b>"))
                .andExpect(jsonPath("$.subjects[2].credential_configuration_ids[0]").value("FarmerCredential"))
                .andReturn();
        assertTrue(answer.getResponse().getContentType().startsWith(MediaType.APPLICATION_JSON_VALUE),
                answer.getResponse().getContentType());
        String body = answer.getResponse().getContentAsString();
        assertTrue(body.contains("\"credential_configuration_ids\""), "the keys are snake_case: " + body);
        assertFalse(body.contains("credentialConfigurationIds"), "no camelCase key leaks the record's Java names: " + body);
    }
}
