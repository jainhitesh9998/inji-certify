/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@EnableCaching
// kernel-keymanager (component scan, JPA, key provisioning) is auto-configured by certify-keyprovider-keymanager
@Import(io.inji.verify.config.AppConfig.class)
@SpringBootApplication(scanBasePackages = "io.mosip.certify," +
        "io.inji.verify.services," +
        "io.inji.verify.key.impl," +
        "io.inji.verify.repository," +
        "io.inji.verify.validator," +
        "${mosip.certify.integration.scan-base-package}")
public class CertifyServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(CertifyServiceApplication.class, args);
    }
}