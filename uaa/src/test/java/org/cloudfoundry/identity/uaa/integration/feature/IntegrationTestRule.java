/*******************************************************************************
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class IntegrationTestRule implements TestRule {
    private static Logger logger = LoggerFactory.getLogger(IntegrationTestRule.class);

    private static Map<String, Boolean> sharedStatuses = new HashMap<>();

    private final String baseUrl;

    public IntegrationTestRule(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    @Override
    public Statement apply(Statement statement, Description description) {
        assertTrue("The UAA server cannot be reached at " + baseUrl, getStatus());
        return statement;
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
        UriComponents components = UriComponentsBuilder.fromHttpUrl(baseUrl).build();
        String host = components.getHost();
        int port = components.getPort();

        logger.info("Testing connectivity for " + baseUrl);
        try (Socket socket = new Socket(host, port)) {
            logger.info("Connectivity test succeeded for " + baseUrl);
            return true;

        } catch (IOException e) {
            logger.warn("Connectivity test failed for " + baseUrl, e);
            return false;
        }
    }
}
