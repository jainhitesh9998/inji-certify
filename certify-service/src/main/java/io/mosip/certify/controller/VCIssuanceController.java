/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.VCIssuanceService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/issuance")
public class VCIssuanceController {

    /** The compatibility credential endpoint (docs/design/09-api-compatibility.md): deprecated from 1.1.0, replaced by {@code POST /oid4vci/credential}. */
    public static final String DEPRECATION_NAME = "oid4vci-v1-compat-credential";
    public static final String DEPRECATED_SINCE = "2026-09-19";

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @Autowired
    MessageSource messageSource;

    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @io.mosip.certify.deprecation.DeprecatedEndpoint(name = DEPRECATION_NAME, since = DEPRECATED_SINCE, replacement = "/oid4vci/credential")
    @PostMapping(value = "/credential",produces = "application/json")
    public CredentialResponse getCredential(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        log.info("Get credential request received for credential configuration id: {}", credentialRequest.getCredentialConfigId());
        return vcIssuanceService.getCredential(credentialRequest);
    }
}