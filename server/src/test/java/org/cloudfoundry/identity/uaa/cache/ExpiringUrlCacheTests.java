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
import org.junit.jupiter.api.*;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;


class ExpiringUrlCacheTests {

    private static final Duration CACHE_EXPIRATION = Duration.ofMinutes(10);
    private ExpiringUrlCache cache;
    private TimeService mockTimeService;
    private RestTemplate template;
    private String uri;
    private byte[] content = new byte[1024];

    @BeforeEach
    void setup() {
        Arrays.fill(content, (byte) 1);
        mockTimeService = mock(TimeService.class);
        when(mockTimeService.getCurrentTimeMillis()).thenAnswer(e -> System.currentTimeMillis());
        cache = new ExpiringUrlCache(CACHE_EXPIRATION, mockTimeService, 2);
        template = mock(RestTemplate.class);
        when(template.getForObject(any(URI.class), any())).thenReturn(content, new byte[1024]);
        uri = "http://localhost:8080/uaa/.well-known/openid-configuration";
    }

    @Test
    void correct_method_invoked_on_rest_template() throws URISyntaxException {
        cache.getUrlContent(uri, template);
        verify(template, times(1)).getForObject(eq(new URI(uri)), same((new byte[0]).getClass()));
    }

    @Test
    void incorrect_uri_throws_illegal_argument_exception() {
        uri = "invalid value";
        assertThrows(IllegalArgumentException.class, () -> cache.getUrlContent(uri, template));
    }

    @Test
    void rest_client_exception_is_propagated() {
        template = mock(RestTemplate.class);
        when(template.getForObject(any(URI.class), any())).thenThrow(new RestClientException("mock"));
        assertThrows(RestClientException.class, () -> cache.getUrlContent(uri, template));
    }

    @Test
    void calling_twice_uses_cache() throws Exception {
        byte[] c1 = cache.getUrlContent(uri, template);
        byte[] c2 = cache.getUrlContent(uri, template);
        verify(template, times(1)).getForObject(eq(new URI(uri)), same((new byte[0]).getClass()));
        assertSame(c1, c2);
        assertEquals(1, cache.size());
    }

    @Test
    void entry_expires_on_time() throws Exception {

        when(mockTimeService.getCurrentTimeMillis())
                .thenReturn(
                        Instant.now().toEpochMilli(),
                        Instant.now()
                                .plus(Duration.ofMinutes(10))
                                .plus(CACHE_EXPIRATION)
                                .toEpochMilli()
                );
        byte[] c1 = cache.getUrlContent(uri, template);
        byte[] c2 = cache.getUrlContent(uri, template);
        verify(template, times(2)).getForObject(eq(new URI(uri)), same((new byte[0]).getClass()));
        assertNotSame(c1, c2);
    }

   @Test
    void cache_should_start_empty() {
        assertEquals(0, cache.size());
    }

    @Test
    void max_entries_is_respected() throws URISyntaxException {
        String uri1 = "http://test1.com";
        String uri2 = "http://test2.com";
        String uri3 = "http://test3.com";
        byte[] c1 = new byte[1024];
        byte[] c2 = new byte[1024];
        byte[] c3 = new byte[1024];
        template = mock(RestTemplate.class);
        when(template.getForObject(eq(new URI(uri1)), any())).thenReturn(c1);
        when(template.getForObject(eq(new URI(uri2)), any())).thenReturn(c2);
        when(template.getForObject(eq(new URI(uri3)), any())).thenReturn(c3);
        for (String uri : Arrays.asList(uri1, uri1, uri2, uri2, uri3, uri3)) {
            cache.getUrlContent(uri, template);
        }
        for (String uri : Arrays.asList(uri1, uri2, uri3)) {
            verify(template, times(1)).getForObject(eq(new URI(uri)), same((new byte[0]).getClass()));
        }
        assertEquals(2, cache.size());
    }

    @Nested
    @DisplayName("When a http server never returns a http response")
    class DeadHttpServer {
        private SlowHttpServer slowHttpServer;

        @BeforeEach
        void startHttpServer() {
            slowHttpServer = new SlowHttpServer();
            slowHttpServer.run();
        }

        @AfterEach
        void stopHttpServer() {
            slowHttpServer.stop();
        }

        @Test
        void throwUnavailableIdpWhenServerMetadataDoesNotReply() {
            RestTemplateConfig restTemplateConfig = new RestTemplateConfig();
            restTemplateConfig.timeout = 120;
            RestTemplate restTemplate = restTemplateConfig.trustingRestTemplate();

            assertTimeout(Duration.ofSeconds(60), () -> assertThrows(ResourceAccessException.class,
                    () -> cache.getUrlContent(slowHttpServer.getUrl(), restTemplate)
            ));
        }
    }

}
