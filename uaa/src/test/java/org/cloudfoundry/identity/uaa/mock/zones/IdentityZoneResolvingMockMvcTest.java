package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneResolvingFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class IdentityZoneResolvingMockMvcTest {

    private Set<String> originalHostnames;

    private MockMvc mockMvc;
    private IdentityZoneResolvingFilter identityZoneResolvingFilter;

    @BeforeEach
    void storeSettings(
            @Autowired MockMvc mockMvc,
            @Autowired IdentityZoneResolvingFilter identityZoneResolvingFilter
    ) {
        this.mockMvc = mockMvc;
        this.identityZoneResolvingFilter = identityZoneResolvingFilter;

        originalHostnames = identityZoneResolvingFilter.getDefaultZoneHostnames();
    }

    @AfterEach
    void restoreSettings() {
        identityZoneResolvingFilter.restoreDefaultHostnames(originalHostnames);
    }

    @Test
    void testSwitchingZones() throws Exception {
        // Authenticate with new Client in new Zone
        mockMvc.perform(
                get("/login")
                        .header("Host", "testsomeother.ip.com")
        )
                .andExpect(status().isOk());
    }

    @Nested
    @DefaultTestContext
    class WithCustomInternalHostnames {

        @BeforeEach
        void setUp() {
            Set<String> hosts = new HashSet<>(Arrays.asList("localhost", "testsomeother.ip.com"));
            identityZoneResolvingFilter.setDefaultInternalHostnames(hosts);
        }

        @ParameterizedTest
        @ValueSource(strings = {"localhost", "testsomeother.ip.com"})
        void isFound(String hostname) throws Exception {
            // Authenticate with new Client in new Zone
            mockMvc.perform(
                    get("/login")
                            .header("Host", hostname)
            )
                    .andExpect(status().isOk());

        }

        @ParameterizedTest
        @ValueSource(strings = {"notlocalhost", "testsomeother2.ip.com"})
        void isNotFound(String hostname) throws Exception {
            mockMvc.perform(
                    get("/login")
                            .header("Host", hostname)
            )
                    .andExpect(status().isNotFound());
        }
    }
}
