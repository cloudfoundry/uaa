package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.junit.Test;
import org.springframework.web.bind.support.SessionStatus;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class FrameworkEndpointHandlerMappingTests {

    private final FrameworkEndpointHandlerMapping mapping = new FrameworkEndpointHandlerMapping();

    @Test
    public void defaults() throws Exception {
        assertEquals("/oauth/token", mapping.getPath("/oauth/token"));
        assertEquals("/oauth/authorize", mapping.getPath("/oauth/authorize"));
        assertEquals("/oauth/error", mapping.getPath("/oauth/error"));
        assertEquals("/oauth/confirm_access", mapping.getPath("/oauth/confirm_access"));
    }

    @Test
    public void mappings() throws Exception {
        mapping.setMappings(Collections.singletonMap("/oauth/token", "/token"));
        assertEquals("/token", mapping.getPath("/oauth/token"));
    }

    @Test
    public void forward() throws Exception {
        mapping.setMappings(Collections.singletonMap("/oauth/confirm_access", "forward:/approve"));
        assertEquals("/approve", mapping.getPath("/oauth/confirm_access"));
    }

    @Test
    public void redirect() throws Exception {
        mapping.setMappings(Collections.singletonMap("/oauth/confirm_access", "redirect:/approve"));
        assertEquals("/approve", mapping.getPath("/oauth/confirm_access"));
    }

    @Test
    public void prefix() throws Exception {
        mapping.setPrefix("/uaa/");
        assertEquals("/uaa/oauth/token", mapping.getServletPath("/oauth/token"));
        mapping.setPrefix(null);
        assertEquals("/oauth/token", mapping.getServletPath("/oauth/token"));
    }

    @Test
    public void getPath() throws Exception {
        assertNotNull(mapping.getPaths());
    }

    @Test
    public void getMappingForMethod() throws Exception {
        mapping.setApprovalParameter("any");
        Method m = UaaAuthorizationEndpoint.class.getMethod("authorize", Map.class, Map.class, SessionStatus.class, Principal.class, HttpServletRequest.class);
        assertNotNull(mapping.getMappingForMethod(m, UaaAuthorizationEndpoint.class));
        assertNull(mapping.getMappingForMethod(UaaAuthorizationEndpoint.class.getMethod("afterPropertiesSet"), UaaAuthorizationEndpoint.class));
        assertFalse(mapping.isHandler(UaaAuthorizationEndpoint.class));
    }
}
