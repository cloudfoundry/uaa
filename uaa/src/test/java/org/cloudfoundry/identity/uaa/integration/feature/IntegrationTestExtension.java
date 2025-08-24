/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.integration.feature;

import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.fail;

/**
 * <pre>
 * &#064;Autowired
 * &#064;RegisterExtension
 * private static IntegrationTestExtension integrationTestExtension;
 * </pre>
 */
public class IntegrationTestExtension implements BeforeEachCallback {
    private static final Logger log = LoggerFactory.getLogger(IntegrationTestExtension.class);

    private static final Map<String, Boolean> sharedStatuses = new HashMap<>();

    @Value("${integration.test.base_url}")
    private String baseUrl;

    public IntegrationTestExtension() {
    }

    public IntegrationTestExtension(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        if (!getStatus()) {
            fail("The UAA server cannot be reached at %s".formatted(baseUrl));
        }
    }

    private synchronized Boolean getStatus() {
        Boolean available = sharedStatuses.get(baseUrl);
        if (available == null) {
            available = connectionAvailable();
            sharedStatuses.put(baseUrl, available);
        }
        return available;
    }

    private boolean connectionAvailable() {
        UriComponents components = UriComponentsBuilder.fromUriString(baseUrl).build();
        String host = components.getHost();
        int port = components.getPort();

        log.info("Testing connectivity for {}", baseUrl);
        try (Socket socket = new Socket(host, port)) {
            log.info("Connectivity test succeeded for {}", baseUrl);
            return true;

        } catch (IOException e) {
            log.warn("Connectivity test failed for {}", baseUrl, e);
            return false;
        }
    }
}
