package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.provider.token.ResourceServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.IntrospectionClaims;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class IntrospectEndpointTest {

    private IntrospectEndpoint introspectEndpoint;

    @Mock
    private ResourceServerTokenServices resourceServerTokenServices;

    private String validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlVBQSB1c2VybmFtZSIsImlhdCI6MTUxNjIzOTAyMn0.jS74pusAMo7VBsEN08rzpxMrk57ZMoRH3QX_gNUopJ4";

    @BeforeEach
    void setUp() {
        introspectEndpoint = new IntrospectEndpoint(resourceServerTokenServices);
    }

    @Test
    void validToken() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);

        when(resourceServerTokenServices.readAccessToken(validToken)).thenReturn(token);
        when(token.isExpired()).thenReturn(false);
        when(token.getValue()).thenReturn(validToken);

        IntrospectionClaims claims = (IntrospectionClaims) introspectEndpoint.introspect(validToken);
        assertThat(claims.isActive()).isTrue();

        verify(resourceServerTokenServices).readAccessToken(validToken);
        verify(resourceServerTokenServices).loadAuthentication(validToken);
        verify(token).isExpired();
    }

    @Test
    void expiredTokenIsInactive() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);

        when(resourceServerTokenServices.readAccessToken(validToken)).thenReturn(token);
        when(token.isExpired()).thenReturn(true);

        Object result = introspectEndpoint.introspect(validToken);
        assertThat(result).isEqualTo(Map.of("active", false));
    }

    @Test
    void invalidToken_inReadAccessToken() {
        when(resourceServerTokenServices.readAccessToken(validToken)).thenThrow(new InvalidTokenException("Bla"));
        Object result = introspectEndpoint.introspect(validToken);
        assertThat(result).isEqualTo(Map.of("active", false));
    }

    @Test
    void invalidToken_inLoadAuthentication() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(resourceServerTokenServices.readAccessToken(validToken)).thenReturn(token);
        when(resourceServerTokenServices.loadAuthentication(validToken)).thenThrow(new InvalidTokenException("Bla"));
        Object result = introspectEndpoint.introspect(validToken);
        assertThat(result).isEqualTo(Map.of("active", false));
    }

    @Test
    void falseRevocableClaimIsNotSuppressedOnActiveToken() {
        // A `false` value on an active token is real information and must still be
        // returned, unlike the inactive-token case where no other fields are present.
        String tokenWithRevocableFalse = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZXZvY2FibGUiOmZhbHNlfQ.jS74pusAMo7VBsEN08rzpxMrk57ZMoRH3QX_gNUopJ4";
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(resourceServerTokenServices.readAccessToken(tokenWithRevocableFalse)).thenReturn(token);
        when(token.isExpired()).thenReturn(false);
        when(token.getValue()).thenReturn(tokenWithRevocableFalse);

        Object result = introspectEndpoint.introspect(tokenWithRevocableFalse);

        assertThat(result).isInstanceOf(IntrospectionClaims.class);
        assertThat(((IntrospectionClaims) result).isRevocable()).isFalse();
        assertThat(JsonUtils.writeValueAsString(result)).contains("\"revocable\":false");
    }

    @Test
    void claimsForValidToken() {
        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(resourceServerTokenServices.readAccessToken(validToken)).thenReturn(token);
        when(token.isExpired()).thenReturn(false);
        when(token.getValue()).thenReturn(validToken);

        IntrospectionClaims claimsResult = (IntrospectionClaims) introspectEndpoint.introspect(validToken);

        assertThat(claimsResult.isActive()).isTrue();
        assertThat(claimsResult.getName()).isEqualTo("UAA username");
    }

    @Test
    void invalidJSONInClaims() {
        String invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e3RoaXMgaXMgbm90IHZhbGlkIEpTT059.LFFpQ0Gc28vd1YIF4OlgVSi2PjCXtImDC6HlJn75sbQ";

        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(resourceServerTokenServices.readAccessToken(invalidToken)).thenReturn(token);
        when(token.isExpired()).thenReturn(false);
        when(token.getValue()).thenReturn(invalidToken);

        Object result = introspectEndpoint.introspect(invalidToken);

        assertThat(result).isEqualTo(Map.of("active", false));
    }
}