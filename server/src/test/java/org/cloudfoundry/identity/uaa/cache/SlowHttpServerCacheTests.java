/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  *******************************************************************************
 */

package org.cloudfoundry.identity.uaa.cache;

import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.provider.SlowHttpServer;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.net.SocketTimeoutException;
import java.time.Duration;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class SlowHttpServerCacheTests {

    private ExpiringUrlCache cache;
    private SlowHttpServer slowHttpServer;

    @Before
    public void setup() {
        TimeService mockTicker = mock(TimeService.class);
        when(mockTicker.getCurrentTimeMillis()).thenAnswer(e -> System.currentTimeMillis());
        cache = new ExpiringUrlCache(Duration.ofMinutes(10), mockTicker, 2);
        slowHttpServer = new SlowHttpServer();
        slowHttpServer.run();
    }

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @After
    public void stopHttpServer() {
        slowHttpServer.stop();
    }

    @Test(timeout = 5000)
    public void throwUnavailableIdpWhenServerMetadataDoesNotReply() {
        RestTemplateConfig restTemplateConfig = new RestTemplateConfig();
        restTemplateConfig.timeout = 120;
        RestTemplate restTemplate = restTemplateConfig.trustingRestTemplate();

        expectedException.expect(ResourceAccessException.class);

        cache.getUrlContent("https://localhost:" + SlowHttpServer.PORT, restTemplate);
    }
}
