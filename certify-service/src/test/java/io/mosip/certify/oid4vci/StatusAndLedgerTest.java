package io.mosip.certify.oid4vci;

import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.services.CredentialLedgerServiceImpl;
import io.mosip.certify.services.StatusListCredentialService;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.FormatConfig;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.StatusConfig;
import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.spi.UnsignedCredential;
import io.mosip.certify.utils.LedgerUtils;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.env.MockEnvironment;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class StatusAndLedgerTest {

    static final IssuanceContext CONTEXT = new IssuanceContext(TenantContext.DEFAULT, null, List.of(), ProtocolVersion.OID4VCI_1_0, "c", Instant.parse("2026-09-18T10:00:00Z"), Map.of());

    static CredentialConfiguration configuration(List<String> purposes) {
        return new CredentialConfiguration(null, "c", "s", "ldp_vc", new FormatConfig.Generic(Map.of("credentialType", "FarmerCredential,VerifiableCredential"), "k"), null,
                new SigningConfig(KeyRef.parse("keymanager:A"), SignatureAlgorithm.EdDSA, "eddsa-rdfc-2022", null, null, "did:web:issuer"), null, null,
                purposes.isEmpty() ? StatusConfig.NONE : new StatusConfig("BitstringStatusList", purposes), null, null);
    }

    @Test
    void statusEntryAttachedOnlyToVc20DocumentsWithPurposes() {
        StatusListCredentialService service = mock(StatusListCredentialService.class);
        doAnswer(inv -> { ((JSONObject) inv.getArgument(0)).put("credentialStatus", new JSONObject(Map.of("type", "BitstringStatusListEntry", "statusListIndex", "7", "statusPurpose", inv.getArgument(1)))); return null; })
                .when(service).addCredentialStatus(any(), anyString());
        BitstringStatusProvider provider = new BitstringStatusProvider(service);
        UnsignedCredential vc2 = new UnsignedCredential("ldp_vc", Map.of("@context", List.of("https://www.w3.org/ns/credentials/v2"), "type", List.of("VerifiableCredential")), Map.of());
        UnsignedCredential vc1 = new UnsignedCredential("ldp_vc", Map.of("@context", List.of("https://www.w3.org/2018/credentials/v1")), Map.of());

        Map<String, Object> withStatus = provider.attach(vc2, configuration(List.of("revocation")), CONTEXT).asMap();
        assertEquals("7", ((Map<?, ?>) withStatus.get("credentialStatus")).get("statusListIndex"));
        assertEquals("revocation", ((Map<?, ?>) withStatus.get("credentialStatus")).get("statusPurpose"));
        assertSame(vc1, provider.attach(vc1, configuration(List.of("revocation")), CONTEXT), "VC 1.1 documents get no entry, as today");
        assertSame(vc2, provider.attach(vc2, configuration(List.of()), CONTEXT));
        assertTrue(provider.supports("ldp_vc") && !provider.supports("dc+sd-jwt"));
    }

    @Test
    void ledgerEntryUsesThePluginDataAndTheSignedDocument() {
        CredentialLedgerServiceImpl ledger = mock(CredentialLedgerServiceImpl.class);
        LedgerUtils utils = mock(LedgerUtils.class);
        when(utils.extractIndexedAttributes(any())).thenAnswer(inv -> Map.of("id", ((JSONObject) inv.getArgument(0)).optString("id")));
        CredentialStatusDetail detail = new CredentialStatusDetail();
        when(utils.extractCredentialStatusDetails(any())).thenReturn(detail);
        MockEnvironment env = new MockEnvironment().withProperty("mosip.certify.issuer.ledger-enabled", "true");
        LedgerListener listener = new LedgerListener(ledger, utils, env);
        Map<String, Object> document = Map.of("id", "urn:uuid:1", "type", List.of("VerifiableCredential"));
        ClaimSet claims = new ClaimSet(Map.of("fullName", "x"), Map.of(DataProviderPluginDataSource.PROVENANCE_DATA, Map.of("id", "2154189532")));
        IssuedCredential issued = new IssuedCredential("ldp_vc", document, "urn:uuid:1", Map.of());

        listener.onIssued(new IssuanceListener.IssuanceEvent(CONTEXT, configuration(List.of("revocation")), claims, List.of(issued), "txn"));

        ArgumentCaptor<Map<String, Object>> indexed = ArgumentCaptor.forClass(Map.class);
        verify(ledger).storeLedgerEntry(eq("urn:uuid:1"), eq("did:web:issuer"), eq("FarmerCredential,VerifiableCredential"), eq(detail), indexed.capture(), eq(LocalDateTime.parse("2026-09-18T10:00:00")));
        assertEquals("2154189532", indexed.getValue().get("id"), "indexed attributes come from the plugin data");

        LedgerListener disabled = new LedgerListener(ledger, utils, new MockEnvironment().withProperty("mosip.certify.issuer.ledger-enabled", "false"));
        disabled.onIssued(new IssuanceListener.IssuanceEvent(CONTEXT, configuration(List.of()), claims, List.of(issued), "txn2"));
        verify(ledger, org.mockito.Mockito.times(1)).storeLedgerEntry(any(), any(), any(), any(), any(), any());
    }

    @Test
    void credentialIdAssignedFromThePrefixWhenAbsent() {
        CredentialIdListener listener = new CredentialIdListener(new MockEnvironment().withProperty("mosip.certify.data-provider-plugin.id-field-prefix-uri", "urn:uuid:"));
        UnsignedCredential without = new UnsignedCredential("ldp_vc", Map.of("type", List.of("VerifiableCredential")), Map.of());
        UnsignedCredential with = new UnsignedCredential("ldp_vc", Map.of("id", "urn:x"), Map.of());
        assertTrue(listener.beforeSign(without, configuration(List.of()), CONTEXT).asMap().get("id").toString().startsWith("urn:uuid:"));
        assertEquals("urn:x", listener.beforeSign(with, configuration(List.of()), CONTEXT).asMap().get("id"));
        assertFalse(new CredentialIdListener(new MockEnvironment()).beforeSign(without, configuration(List.of()), CONTEXT).asMap().containsKey("id"));
    }
}
