package io.mosip.certify.keyprovider.keymanager;

import io.mosip.certify.signing.KeyRequirement;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.SymmetricKeyGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.boot.DefaultApplicationArguments;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.calls;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class KeymanagerKeyInitializerTest {

    final KeymanagerService keymanagerService = mock(KeymanagerService.class);
    final KeymanagerKeyProvider provider = spy(new KeymanagerKeyProvider(keymanagerService, mock(io.mosip.kernel.signature.service.SignatureServicev2.class),
            List.of(), Clock.systemUTC(), Duration.ofMinutes(1)));

    static final Map<String, List<List<String>>> DEFAULT_MAPPER = Map.of(
            "RS256", List.of(List.of("CERTIFY_VC_SIGN_RSA", "")),
            "EdDSA", List.of(List.of("CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN")),
            "ES256K", List.of(List.of("CERTIFY_VC_SIGN_EC_K1", "EC_SECP256K1_SIGN")),
            "ES256", List.of(List.of("CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN")));

    @Test
    void dataProviderModeCreatesMasterKeysThenTheFourSigningKeys() {
        KeymanagerKeyInitializer initializer = new KeymanagerKeyInitializer(keymanagerService, provider, "TRANSACTION_CACHE", "DataProvider", DEFAULT_MAPPER);

        initializer.run(new DefaultApplicationArguments());

        InOrder order = inOrder(keymanagerService, provider);
        ArgumentCaptor<KeyPairGenerateRequestDto> master = ArgumentCaptor.forClass(KeyPairGenerateRequestDto.class);
        order.verify(keymanagerService, calls(1)).generateMasterKey(eq("CSR"), master.capture());
        assertEquals("ROOT", master.getValue().getApplicationId());
        order.verify(keymanagerService, calls(1)).generateMasterKey(eq("CSR"), master.capture());
        assertEquals("CERTIFY_SERVICE", master.getValue().getApplicationId());
        assertEquals("", master.getValue().getReferenceId());
        ArgumentCaptor<SymmetricKeyGenerateRequestDto> symmetric = ArgumentCaptor.forClass(SymmetricKeyGenerateRequestDto.class);
        order.verify(keymanagerService, calls(1)).generateSymmetricKey(symmetric.capture());
        assertEquals("TRANSACTION_CACHE", symmetric.getValue().getReferenceId());
        assertEquals("CERTIFY_SERVICE", symmetric.getValue().getApplicationId());
        order.verify(keymanagerService, calls(1)).generateMasterKey(eq("CSR"), master.capture());
        assertEquals("CERTIFY_PARTNER", master.getValue().getApplicationId());

        @SuppressWarnings("unchecked") ArgumentCaptor<List<KeyRequirement>> required = ArgumentCaptor.forClass(List.class);
        order.verify(provider, calls(1)).ensureKeys(required.capture());
        assertEquals(List.of("CERTIFY_VC_SIGN_RSA", "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", "CERTIFY_VC_SIGN_EC_K1/EC_SECP256K1_SIGN", "CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN"),
                required.getValue().stream().map(KeyRequirement::alias).toList(), "the default mapper adds nothing beyond the historical four");
    }

    @Test
    void otherPluginModesOnlyCreateMasterKeys() {
        new KeymanagerKeyInitializer(keymanagerService, provider, "", "VCIssuance", DEFAULT_MAPPER).run(new DefaultApplicationArguments());

        verify(keymanagerService, never()).generateSymmetricKey(any());
        verify(provider, never()).ensureKeys(any());
        verify(keymanagerService, times(3)).generateMasterKey(eq("CSR"), any());
    }

    @Test
    void mapperEntriesBeyondTheFourAreCreatedAndUnsupportedAlgorithmsSkipped() {
        Map<String, List<List<String>>> mapper = Map.of(
                "ES256", List.of(List.of("CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN"), List.of("MDL_DSC", "IACA_2026")),
                "ES384", List.of(List.of("MDL_DSC_384", "")));
        KeymanagerKeyInitializer initializer = new KeymanagerKeyInitializer(keymanagerService, provider, null, "DataProvider", mapper);

        List<KeyRequirement> required = initializer.signingKeyRequirements();

        assertEquals(5, required.size());
        assertEquals("MDL_DSC/IACA_2026", required.get(4).alias());
        assertEquals(SignatureAlgorithm.ES256, required.get(4).algorithm());
    }
}
