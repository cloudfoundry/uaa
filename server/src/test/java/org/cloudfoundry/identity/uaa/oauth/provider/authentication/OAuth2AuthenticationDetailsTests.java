package org.cloudfoundry.identity.uaa.oauth.provider.authentication;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.util.SerializationUtils;

import static org.junit.Assert.assertEquals;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2AuthenticationDetailsTests {

    @Test
    public void testSerializationWithDetails() {
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
        assertEquals(holder, other);
        assertEquals(holder.hashCode(), other.hashCode());
        assertEquals(holder.toString(), other.toString());
        assertEquals(holder.getSessionId(), other.getSessionId());
        assertEquals(holder.getRemoteAddress(), other.getRemoteAddress());
        assertEquals(holder.getTokenType(), other.getTokenType());
        assertEquals(holder.getTokenValue(), other.getTokenValue());
    }

}
