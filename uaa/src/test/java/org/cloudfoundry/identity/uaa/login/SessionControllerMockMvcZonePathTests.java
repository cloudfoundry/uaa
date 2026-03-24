package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@DefaultTestContext
@EnabledIfZonePathsEnabled
class SessionControllerMockMvcZonePathTests {

    private final AlphanumericRandomValueStringGenerator subdomainGenerator = new AlphanumericRandomValueStringGenerator();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @BeforeEach
    void setUp() {
        // No per-test setup required; zone is created inside each parameterized test
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void sessionEndpointWhichSupportsLegacyUaaSingular(ZoneResolutionMode mode) throws Exception {
        String subdomain = subdomainGenerator.generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/session")
                        .param("clientId", "1")
                        .param("messageOrigin", "origin"))
                .andExpect(status().isOk())
                .andExpect(view().name("session"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void sessionManagementEndpointWhichSupportsUaaSingular(ZoneResolutionMode mode) throws Exception {
        String subdomain = subdomainGenerator.generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/session_management")
                        .param("clientId", "1")
                        .param("messageOrigin", "origin"))
                .andExpect(status().isOk())
                .andExpect(view().name("session_management"));
    }
}
