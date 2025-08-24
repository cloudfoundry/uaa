package org.cloudfoundry.identity.uaa.mock.config;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.security.web.SecurityFilterChainPostProcessor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.stream.Stream;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
//@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class HealthzShouldNotBeProtectedMockMvcTests {

    private SecurityFilterChainPostProcessor chainPostProcessor;
    private boolean originalRequireHttps;
    private MockMvc mockMvc;

    @BeforeEach
    void beforeEach(
            @Autowired SecurityFilterChainPostProcessor securityFilterChainPostProcessor,
            @Autowired MockMvc mockMvc
    ) throws Exception {
        this.mockMvc = mockMvc;
        chainPostProcessor = securityFilterChainPostProcessor;
        originalRequireHttps = securityFilterChainPostProcessor.isRequireHttps();
        mockMvc.perform(get("/login"));
    }

    @AfterEach
    void afterEach() {
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
        void beforeEach() {
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
                    .andExpect(status().is3xxRedirection())
                    .andExpect(header().string("Location", "https://localhost/login"));
        }

        @Test
        void samlMetadataRedirects() throws Exception {
            MockHttpServletRequestBuilder getRequest = get("/saml/metadata")
                    .accept(MediaType.ALL);

            mockMvc.perform(getRequest)
                    .andExpect(status().is3xxRedirection())
                    .andExpect(header().string("Location", "https://localhost/saml/metadata"));
        }

        @DefaultTestContext
        @Nested
        class WithHttpPortSetToNonDefaultValue {
            @BeforeEach
            void setUp() {
                chainPostProcessor.setHttpsPort(9998);
            }

            @Test
            void redirectedRequestsGoToTheConfiguredPort() throws Exception {
                MockHttpServletRequestBuilder getRequest = get("/login")
                        .accept(MediaType.TEXT_HTML);

                mockMvc.perform(getRequest)
                        .andExpect(status().is3xxRedirection())
                        .andExpect(header().string("Location", "https://localhost:9998/login"));
            }
        }
    }

    @DefaultTestContext
    @Nested
    class WithHttpsNotRequired {

        @BeforeEach
        void beforeEach() {
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
                    .andDo(print())
                    .andExpect(status().isOk());
        }
    }
}
