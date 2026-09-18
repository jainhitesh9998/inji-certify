package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.ProofType;
import io.mosip.certify.core.spi.VCIssuanceService;

import io.mosip.certify.services.VCICacheService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The kill switch of the compatibility credential endpoint answers 410 Gone (CLAUDE.md rule 6). */
@WebMvcTest(value = VCIssuanceController.class)
@TestPropertySource(properties = "mosip.certify.deprecated." + VCIssuanceController.DEPRECATION_NAME + ".enabled=false")
class VCIssuanceControllerKillSwitchTest {

    ObjectMapper objectMapper = new ObjectMapper();
    @Autowired MockMvc mockMvc;
    @MockBean AuditPlugin auditWrapper;
    @MockBean ParsedAccessToken parsedAccessToken;
    @MockBean io.mosip.certify.dpop.DpopProofValidator dpopProofValidator;
    @MockBean VCIssuanceService vcIssuanceService;
    @MockBean VCICacheService vciCacheService;

    @Test
    void disabledCompatibilityEndpointAnswersGone() throws Exception {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setProofs(Map.of(ProofType.JWT, List.of("dummy_jwt_proof")));
        credentialRequest.setCredentialConfigId("FarmerCredential");
        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isGone());
    }
}
