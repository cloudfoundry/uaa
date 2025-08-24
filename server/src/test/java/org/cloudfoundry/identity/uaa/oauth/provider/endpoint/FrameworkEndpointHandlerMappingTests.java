package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.support.SessionStatus;

import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class FrameworkEndpointHandlerMappingTests {

    private final FrameworkEndpointHandlerMapping mapping = new FrameworkEndpointHandlerMapping();

    @Test
    void defaults() {
        assertThat(mapping.getPath("/oauth/token")).isEqualTo("/oauth/token");
        assertThat(mapping.getPath("/oauth/authorize")).isEqualTo("/oauth/authorize");
        assertThat(mapping.getPath("/oauth/error")).isEqualTo("/oauth/error");
        assertThat(mapping.getPath("/oauth/confirm_access")).isEqualTo("/oauth/confirm_access");
    }

    @Test
    void mappings() {
        mapping.setMappings(Collections.singletonMap("/oauth/token", "/token"));
        assertThat(mapping.getPath("/oauth/token")).isEqualTo("/token");
    }

    @Test
    void forward() {
        mapping.setMappings(Collections.singletonMap("/oauth/confirm_access", "forward:/approve"));
        assertThat(mapping.getPath("/oauth/confirm_access")).isEqualTo("/approve");
    }

    @Test
    void redirect() {
        mapping.setMappings(Collections.singletonMap("/oauth/confirm_access", "redirect:/approve"));
        assertThat(mapping.getPath("/oauth/confirm_access")).isEqualTo("/approve");
    }

    @Test
    void prefix() {
        mapping.setPrefix("/uaa/");
        assertThat(mapping.getServletPath("/oauth/token")).isEqualTo("/uaa/oauth/token");
        mapping.setPrefix(null);
        assertThat(mapping.getServletPath("/oauth/token")).isEqualTo("/oauth/token");
    }

    @Test
    void getPath() {
        assertThat(mapping.getPaths()).isNotNull();
    }

    @Test
    void getMappingForMethod() throws Exception {
        mapping.setApprovalParameter("any");
        Method m = UaaAuthorizationEndpoint.class.getMethod("authorize", Map.class, Map.class, SessionStatus.class, Principal.class, HttpServletRequest.class);
        assertThat(mapping.getMappingForMethod(m, UaaAuthorizationEndpoint.class)).isNotNull();
        assertThat(mapping.getMappingForMethod(UaaAuthorizationEndpoint.class.getMethod("afterPropertiesSet"), UaaAuthorizationEndpoint.class)).isNull();
        assertThat(mapping.isHandler(UaaAuthorizationEndpoint.class)).isFalse();
    }
}
