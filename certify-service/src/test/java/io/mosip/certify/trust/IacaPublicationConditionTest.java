package io.mosip.certify.trust;

import io.mosip.certify.signing.TrustAnchorRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.http.CacheControl;

import java.security.cert.X509CRL;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** M-08 is off unless {@code certify.pki.publication.enabled}: neither the controller nor its security chain exists. */
class IacaPublicationConditionTest {

    final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withBean(TrustAnchorRegistry.class, () -> TrustAnchorRegistry.EMPTY)
            .withUserConfiguration(IacaPublicationController.class, IacaPublicationSecurityConfiguration.class);

    @Test
    void thePublicationIsOffByDefault() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(IacaPublicationController.class);
            assertThat(context).doesNotHaveBean(IacaPublicationSecurityConfiguration.class);
        });
        runner.withPropertyValues("certify.pki.publication.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(IacaPublicationController.class));
    }

    @Test
    void enabledItServesTheRegistry() {
        runner.withPropertyValues("certify.pki.publication.enabled=true")
                .withPropertyValues("spring.profiles.active=test") // the chain needs HttpSecurity, which the test profile omits
                .run(context -> assertThat(context).hasSingleBean(IacaPublicationController.class));
    }

    @Test
    void aCrlIsCachedUntilItsNextUpdateAndAtMostAnHour() {
        Instant now = Instant.parse("2026-11-13T00:00:00Z");
        assertEquals(CacheControl.maxAge(java.time.Duration.ofMinutes(10)).cachePublic().getHeaderValue(),
                IacaPublicationController.crlCache(crl(now.plusSeconds(600)), now).getHeaderValue());
        assertEquals(CacheControl.maxAge(java.time.Duration.ofHours(1)).cachePublic().getHeaderValue(),
                IacaPublicationController.crlCache(crl(now.plusSeconds(86_400)), now).getHeaderValue());
        assertEquals(CacheControl.noCache().getHeaderValue(), IacaPublicationController.crlCache(crl(now.minusSeconds(1)), now).getHeaderValue(),
                "a CRL past its nextUpdate is not cached");
    }

    private static X509CRL crl(Instant nextUpdate) {
        X509CRL crl = mock(X509CRL.class);
        when(crl.getNextUpdate()).thenReturn(Date.from(nextUpdate));
        return crl;
    }
}
