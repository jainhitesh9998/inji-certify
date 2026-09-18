package io.mosip.certify.configv2;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * {@code /v2/credential-configurations} (docs/design/09-api-compatibility.md): the domain model in and out, HTTP status
 * codes and {@code {error, error_description}} bodies, and {@code POST /{id}/preview} as the dry run of a saved row.
 * The path sits under the same {@code credential-configurations} security patterns as the v1 API.
 */
@RestController
@RequestMapping("/v2/credential-configurations")
public class CredentialConfigurationV2Controller {

    private final CredentialConfigurationV2Service service;

    public CredentialConfigurationV2Controller(CredentialConfigurationV2Service service) {
        this.service = service;
    }

    @PostMapping(consumes = "application/json", produces = "application/json")
    public ResponseEntity<CredentialConfigurationV2> create(@RequestBody CredentialConfigurationV2 body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(body));
    }

    @GetMapping(produces = "application/json")
    public List<CredentialConfigurationV2> list() {
        return service.list();
    }

    @GetMapping(value = "/{id}", produces = "application/json")
    public CredentialConfigurationV2 get(@PathVariable String id) {
        return service.get(id);
    }

    @PutMapping(value = "/{id}", consumes = "application/json", produces = "application/json")
    public CredentialConfigurationV2 update(@PathVariable String id, @RequestBody CredentialConfigurationV2 body) {
        return service.update(id, body);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping(value = "/{id}/preview", consumes = "application/json", produces = "application/json")
    public CredentialConfigurationV2.PreviewResponse preview(@PathVariable String id, @RequestBody(required = false) CredentialConfigurationV2.PreviewRequest request) {
        return service.preview(id, request);
    }

    @ExceptionHandler(ConfigV2Exception.class)
    public ResponseEntity<Map<String, String>> refused(ConfigV2Exception e) {
        return ResponseEntity.status(e.status()).body(Map.of("error", e.code(), "error_description", String.valueOf(e.getMessage())));
    }
}
