package org.cloudfoundry.identity.uaa.oauth.provider.authentication;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.util.SerializationUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2AuthenticationDetailsTests {

    @Test
    void serializationWithDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession mockHttpSession = new MockHttpSession();
        mockHttpSession.changeSessionId();
        request.setRequestedSessionId("id");
        request.setSession(mockHttpSession);
        request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, "FOO");
        request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, "bearer");
        OAuth2AuthenticationDetails holder = new OAuth2AuthenticationDetails(request);
        OAuth2AuthenticationDetails other = (OAuth2AuthenticationDetails) SerializationUtils.deserialize(SerializationUtils
                .serialize(holder));
        assertThat(other).isEqualTo(holder)
                .hasSameHashCodeAs(holder)
                .hasToString(holder.toString());
        assertThat(other.getSessionId()).isEqualTo(holder.getSessionId());
        assertThat(other.getRemoteAddress()).isEqualTo(holder.getRemoteAddress());
        assertThat(other.getTokenType()).isEqualTo(holder.getTokenType());
        assertThat(other.getTokenValue()).isEqualTo(holder.getTokenValue());
    }
}
