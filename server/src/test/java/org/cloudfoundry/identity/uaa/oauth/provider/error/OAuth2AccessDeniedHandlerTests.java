package org.cloudfoundry.identity.uaa.oauth.provider.error;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

import jakarta.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2AccessDeniedHandlerTests {

    private final OAuth2AccessDeniedHandler handler = new OAuth2AccessDeniedHandler();

    private final MockHttpServletRequest request = new MockHttpServletRequest();

    private final MockHttpServletResponse response = new MockHttpServletResponse();

    @Test
    void handleWithJson() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        handler.handle(request, response, new AccessDeniedException("Bad"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentType()).contains(MediaType.APPLICATION_JSON_VALUE);
        assertThat(response.getErrorMessage()).isNull();
    }

    @Test
    void handleSetter() {
        handler.setExceptionRenderer(new DefaultOAuth2ExceptionRenderer());
        handler.setExceptionTranslator(new DefaultWebResponseExceptionTranslator());
        assertThatNoException().isThrownBy(() -> handler.doHandle(request, response, new AccessDeniedException("Bad")));
    }
}
