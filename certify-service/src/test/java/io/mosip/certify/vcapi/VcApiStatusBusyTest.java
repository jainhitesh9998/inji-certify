package io.mosip.certify.vcapi;

import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.services.StatusListBusyException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * M-11d review round 5, finding 1, the VC-API surface: a status change refused because the list's lock was not
 * available within {@code certify.status.update.lock-wait} is {@code 503} with {@code Retry-After} and a problem body
 * naming {@value StatusListBusyException#ERROR_CODE} — the client may send the same request again — while every other
 * refusal keeps its mapping. On PostgreSQL end to end: {@code StatusListPostgresTest}.
 */
class VcApiStatusBusyTest {

    private final CredentialStatusService statusService = mock(CredentialStatusService.class);
    private final VcApiController controller = new VcApiController(null, null, null, null, statusService);

    private static Map<String, Object> request() {
        return Map.of("credentialId", "urn:uuid:1", "status", true, "credentialStatus", Map.of(
                "type", "TokenStatusListEntry", "statusPurpose", "revocation",
                "statusListCredential", "list-1", "statusListIndex", 7));
    }

    @Test
    void aBusyListIs503WithRetryAfter() {
        when(statusService.updateCredentialStatus(any())).thenThrow(
                new StatusListBusyException("list-1", Duration.ofSeconds(5), null));

        ResponseEntity<Map<String, Object>> response = controller.status(request());

        assertEquals(503, response.getStatusCode().value());
        assertEquals("5", response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER));
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
        assertEquals("status_list_busy_retry_later", response.getBody().get("title"));
        assertEquals("urn:mosip:certify:vc-api:status_list_busy_retry_later", response.getBody().get("type"));
    }

    @Test
    void otherRefusalsKeepTheirMapping() {
        when(statusService.updateCredentialStatus(any())).thenThrow(new CertifyException(
                "requested_index_is_out_of_bounds_for_status_list_capacity", "outside"));

        ResponseEntity<Map<String, Object>> response = controller.status(request());

        assertEquals(400, response.getStatusCode().value());
        assertNull(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER));
    }
}
