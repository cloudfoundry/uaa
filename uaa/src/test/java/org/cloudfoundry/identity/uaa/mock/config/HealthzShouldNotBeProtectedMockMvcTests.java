/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.mock.config;

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.security.web.SecurityFilterChainPostProcessor;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.stream.Stream;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Configuration
class TestClientMockMvc {
    @Bean
    public MockMvc mockMvc(
            WebApplicationContext webApplicationContext,
            @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") FilterChainProxy springSecurityFilterChain
    ) {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();
    }

    @Bean
    public TestClient testClient(
            MockMvc mockMvc
    ) {
        return new TestClient(mockMvc);
    }
}

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(SpringExtension.class)
@ExtendWith(HoneycombJdbcInterceptorExtension.class)
@ExtendWith(HoneycombAuditEventTestListenerExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = {
        TestSpringContext.class,
        TestClientMockMvc.class
})
@interface DefaultTestContext {
}

@DefaultTestContext
class HealthzShouldNotBeProtectedMockMvcTests {

    private SecurityFilterChainPostProcessor chainPostProcessor;
    private boolean originalRequireHttps;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp(
            @Autowired SecurityFilterChainPostProcessor securityFilterChainPostProcessor,
            @Autowired MockMvc mockMvc
    ) {
        this.mockMvc = mockMvc;
        chainPostProcessor = securityFilterChainPostProcessor;
        originalRequireHttps = securityFilterChainPostProcessor.isRequireHttps();
    }

    @AfterEach
    void tearDown() {
        chainPostProcessor.setRequireHttps(originalRequireHttps);
    }

    static class HealthzGetRequestParams implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(get("/healthz").accept(MediaType.APPLICATION_JSON)),
                    Arguments.of(get("/healthz").accept(MediaType.TEXT_HTML)),
                    Arguments.of(get("/healthz").accept(MediaType.ALL))
            );
        }
    }

    @DefaultTestContext
    @Nested
    class WithHttpsRequired {

        @BeforeEach
        void setUp() {
            chainPostProcessor.setRequireHttps(true);
        }

        @ParameterizedTest
        @ArgumentsSource(HealthzGetRequestParams.class)
        void healthzIsNotRejected(MockHttpServletRequestBuilder getRequest) throws Exception {
            mockMvc.perform(getRequest)
                    .andExpect(status().isOk())
                    .andExpect(content().string("ok\n"));
        }

        @Test
        void loginRedirects() throws Exception {
            MockHttpServletRequestBuilder getRequest = get("/login")
                    .accept(MediaType.TEXT_HTML);

            mockMvc.perform(getRequest)
                    .andExpect(status().is3xxRedirection());
        }

        @Test
        void samlMetadataRedirects() throws Exception {
            MockHttpServletRequestBuilder getRequest = get("/saml/metadata")
                    .accept(MediaType.ALL);

            mockMvc.perform(getRequest)
                    .andExpect(status().is3xxRedirection());
        }
    }

    @DefaultTestContext
    @Nested
    class WithHttpsNotRequired {

        @BeforeEach
        void setUp() {
            chainPostProcessor.setRequireHttps(false);
        }

        @ParameterizedTest
        @ArgumentsSource(HealthzGetRequestParams.class)
        void healthzIsNotRejected(MockHttpServletRequestBuilder getRequest) throws Exception {
            mockMvc.perform(getRequest)
                    .andExpect(status().isOk())
                    .andExpect(content().string("ok\n"));
        }

        @Test
        void loginReturnsOk() throws Exception {
            MockHttpServletRequestBuilder getRequest = get("/login")
                    .accept(MediaType.TEXT_HTML);

            mockMvc.perform(getRequest)
                    .andExpect(status().isOk());
        }

        @Test
        void samlMetadataReturnsOk() throws Exception {
            MockHttpServletRequestBuilder getRequest = get("/saml/metadata")
                    .accept(MediaType.ALL);

            mockMvc.perform(getRequest)
                    .andExpect(status().isOk());
        }
    }
}
