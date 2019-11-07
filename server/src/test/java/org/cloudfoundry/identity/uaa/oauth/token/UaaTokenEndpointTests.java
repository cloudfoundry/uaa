package org.cloudfoundry.identity.uaa.oauth.token;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static java.util.Collections.emptyMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

class UaaTokenEndpointTests {

    private HashSet<HttpMethod> allowedRequestMethods;
    private UaaTokenEndpoint endpoint;

    private ResponseEntity response;

    @BeforeEach
    void setup() {
        allowedRequestMethods = new HashSet<>(Arrays.asList(POST, GET));
        endpoint = spy(new UaaTokenEndpoint());
        endpoint.setAllowedRequestMethods(allowedRequestMethods);
        response = mock(ResponseEntity.class);
    }

    @Test
    void allowsGetByDefault() throws Exception {
        doReturn(response).when(endpoint).postAccessToken(any(), any());
        ResponseEntity<OAuth2AccessToken> result = endpoint.doDelegateGet(mock(Principal.class), emptyMap());
        assertSame(response, result);
    }

    @Test
    void getIsDisabled() throws Exception {
        endpoint.setAllowQueryString(false);
        ResponseEntity response = mock(ResponseEntity.class);
        doReturn(response).when(endpoint).postAccessToken(any(), any());
        assertThrows(HttpRequestMethodNotSupportedException.class,
                () -> endpoint.doDelegateGet(mock(Principal.class), emptyMap()));
    }

    @Test
    void postAllowsQueryStringByDefault() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getQueryString()).thenReturn("some-parameter=some-value");
        doReturn(response).when(endpoint).postAccessToken(any(), any());
        ResponseEntity<OAuth2AccessToken> result = endpoint.doDelegatePost(mock(Principal.class), emptyMap(), request);
        assertSame(response, result);
    }

    @Test
    void setAllowedRequestMethods() {
        Set<HttpMethod> methods = (Set<HttpMethod>) ReflectionTestUtils.getField(endpoint, "allowedRequestMethods");
        assertNotNull(methods);
        assertEquals(2, methods.size());
        assertThat(methods, containsInAnyOrder(POST, GET));
    }

    @Test
    void callToGetAlwaysThrowsSuperMethod() {
        UaaTokenEndpoint endpoint = new UaaTokenEndpoint();
        endpoint.setAllowedRequestMethods(allowedRequestMethods);
        endpoint.setAllowQueryString(false);

        HttpRequestMethodNotSupportedException e =
                assertThrows(
                        HttpRequestMethodNotSupportedException.class,
                        () -> endpoint.getAccessToken(mock(Principal.class), emptyMap()));
        assertEquals("GET", e.getMethod());
    }

    @Test
    void callToGetAlwaysThrowsOverrideMethod() {
        UaaTokenEndpoint endpoint = new UaaTokenEndpoint();
        endpoint.setAllowedRequestMethods(allowedRequestMethods);
        endpoint.setAllowQueryString(false);

        HttpRequestMethodNotSupportedException e =
                assertThrows(
                        HttpRequestMethodNotSupportedException.class,
                        () -> endpoint.doDelegateGet(mock(Principal.class), emptyMap()));
        assertEquals("GET", e.getMethod());
    }
}