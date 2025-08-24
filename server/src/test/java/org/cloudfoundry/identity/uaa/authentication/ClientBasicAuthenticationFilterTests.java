package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ClientBasicAuthenticationFilterTests {
    private ClientBasicAuthenticationFilter filter;
    private AuthenticationManager clientAuthenticationManager;
    private AuthenticationDetailsSource<HttpServletRequest, ?> uaaAuthenticationDetailsSource;
    private AuthenticationEntryPoint mockEntryPoint;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        IdentityZone testZone = new IdentityZone();
        IdentityZoneHolder.set(testZone);

        clientAuthenticationManager = mock(AuthenticationManager.class);
        uaaAuthenticationDetailsSource = mock(UaaAuthenticationDetailsSource.class);
        mockEntryPoint = mock(AuthenticationEntryPoint.class);
    }

    @AfterAll
    static void tearDown() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Nested
    class ByDefault {
        @BeforeEach
        void setUp() {
            filter = new ClientBasicAuthenticationFilter(clientAuthenticationManager, mockEntryPoint, false);
            filter.setAuthenticationDetailsSource(uaaAuthenticationDetailsSource);
        }

        @Test
        void urlDecodesClientIdAndClientSecret() throws IOException, ServletException {
            String clientId = "app|whatever";
            String clientSecret = "sec|ret";
            MockFilterChain chain = mock(MockFilterChain.class);
            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();
            addBasicAuthHeaderWithEncoding(request, clientId, clientSecret);

            filter.doFilter(request, response, chain);

            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(clientId, clientSecret);
            token.setDetails(uaaAuthenticationDetailsSource.buildDetails(request));
            verify(clientAuthenticationManager).authenticate(token);
            assertThat(request.getAttribute("clientId")).isEqualTo(clientId);
        }

        @Test
        void urlFailsGracefullyWhenEncodedBadly() throws IOException, ServletException {
            String clientId = "app|whatever";
            String clientSecret = "sec%ret";
            MockFilterChain chain = mock(MockFilterChain.class);
            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();
            addBasicAuthHeaderWithoutEncoding(request, clientId, clientSecret);

            filter.doFilter(request, response, chain);

            verify(mockEntryPoint).commence(any(), any(), any(AuthenticationException.class));
        }
    }

    @Nested
    class WithUriEncodingCompatibilityMode {
        @BeforeEach
        void setUp() {
            filter = new ClientBasicAuthenticationFilter(clientAuthenticationManager, mockEntryPoint, true);
            filter.setAuthenticationDetailsSource(uaaAuthenticationDetailsSource);
        }

        @Test
        void doesNotDecodeClientIdAndClientSecretByDefault() throws IOException, ServletException {
            String clientId = "app%whatever";
            String clientSecret = "sec%ret";
            MockFilterChain chain = mock(MockFilterChain.class);
            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();
            addBasicAuthHeaderWithoutEncoding(request, clientId, clientSecret);

            filter.doFilter(request, response, chain);

            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(clientId, clientSecret);
            token.setDetails(uaaAuthenticationDetailsSource.buildDetails(request));
            verify(clientAuthenticationManager).authenticate(token);
            assertThat(request.getAttribute("clientId")).isEqualTo(clientId);
        }

        @Test
        void decodeClientIdAndClientSecretWhenHeaderProvided() throws IOException, ServletException {
            String clientId = "app%whatever";
            String clientSecret = "sec%ret";
            MockFilterChain chain = mock(MockFilterChain.class);
            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();
            addBasicAuthHeaderWithEncoding(request, clientId, clientSecret);
            request.addHeader("X-CF-ENCODED-CREDENTIALS", "true");

            filter.doFilter(request, response, chain);

            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(clientId, clientSecret);
            token.setDetails(uaaAuthenticationDetailsSource.buildDetails(request));
            verify(clientAuthenticationManager).authenticate(token);
            assertThat(request.getAttribute("clientId")).isEqualTo(clientId);
        }
    }

    private void addBasicAuthHeaderWithEncoding(MockHttpServletRequest request, String clientId, String clientSecret) {
        String encodedClientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
        String encodedClientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        String encodedCredentials = new String(
                Base64.getEncoder().encode((encodedClientId + ":" + encodedClientSecret).getBytes())
        );

        request.addHeader("Authorization", "Basic " + encodedCredentials);
    }

    private void addBasicAuthHeaderWithoutEncoding(MockHttpServletRequest request, String clientId, String clientSecret) {
        String credentials = new String(
                Base64.getEncoder().encode((clientId + ":" + clientSecret).getBytes())
        );

        request.addHeader("Authorization", "Basic " + credentials);
    }
}