package org.cloudfoundry.identity.uaa.oauth.token;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@ExtendWith(MockitoExtension.class)
class UaaTokenEndpointTests {

    private UaaTokenEndpoint endpoint;

    @Mock
    private ResponseEntity mockResponseEntity;

    @BeforeEach
    void setup() {
        endpoint = spy(new UaaTokenEndpoint(null, null, null, null, null));
    }

    @Test
    void allowsGetByDefault() throws Exception {
        doReturn(mockResponseEntity).when(endpoint).postAccessToken(any(), any());
        ResponseEntity<OAuth2AccessToken> result = endpoint.doDelegateGet(mock(Principal.class), emptyMap());
        assertThat(result).isSameAs(mockResponseEntity);
    }

    @Test
    void getIsDisabled() {
        endpoint = spy(new UaaTokenEndpoint(null, null, null, null, false));
        assertThatThrownBy(() -> endpoint.doDelegateGet(mock(Principal.class), emptyMap())).asInstanceOf(InstanceOfAssertFactories.throwable(HttpRequestMethodNotSupportedException.class));
    }

    @Test
    void postAllowsQueryStringByDefault() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getQueryString()).thenReturn("some-parameter=some-value");
        doReturn(mockResponseEntity).when(endpoint).postAccessToken(any(), any());
        ResponseEntity<OAuth2AccessToken> result = endpoint.doDelegatePost(mock(Principal.class), emptyMap(), request);
        assertThat(result).isSameAs(mockResponseEntity);
    }

    @Test
    void setAllowedRequestMethods() {
        Set<HttpMethod> methods = (Set<HttpMethod>) ReflectionTestUtils.getField(endpoint, "allowedRequestMethods");
        assertThat(methods)
                .containsExactlyInAnyOrder(POST, GET);
    }

    @Test
    void mapsMtlsTokenEndpointAndItsDescendants() throws NoSuchMethodException {
        RequestMapping mapping = UaaTokenEndpoint.class.getAnnotation(RequestMapping.class);

        assertThat(mapping.value())
                .contains("/oauth/mtls/token");
        assertThat(UaaTokenEndpoint.class.getDeclaredMethod("doDelegateGet", Principal.class, Map.class)
                .getAnnotation(GetMapping.class).value())
                .containsExactly("**");
        assertThat(UaaTokenEndpoint.class.getDeclaredMethod("doDelegatePost", Principal.class, Map.class,
                HttpServletRequest.class).getAnnotation(PostMapping.class).value())
                .containsExactly("**");
    }

    @Test
    void callToGetAlwaysThrowsSuperMethod() {
        endpoint = new UaaTokenEndpoint(null, null, null, null, false);

        assertThatThrownBy(() -> endpoint.getAccessToken(mock(Principal.class), emptyMap()))
                .isInstanceOf(HttpRequestMethodNotSupportedException.class)
                .satisfies(e -> assertThat(((HttpRequestMethodNotSupportedException) e).getMethod()).isEqualTo("GET"));
    }

    @Test
    void callToGetAlwaysThrowsOverrideMethod() {
        endpoint = new UaaTokenEndpoint(null, null, null, null, false);

        assertThatThrownBy(() -> endpoint.doDelegateGet(mock(Principal.class), emptyMap()))
                .isInstanceOf(HttpRequestMethodNotSupportedException.class)
                .satisfies(e -> assertThat(((HttpRequestMethodNotSupportedException) e).getMethod()).isEqualTo("GET"));
    }
}
