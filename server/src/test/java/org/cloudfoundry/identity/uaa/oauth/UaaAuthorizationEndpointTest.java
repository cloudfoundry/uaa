package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UaaAuthorizationEndpointTest {

    private OAuth2RequestFactory oAuth2RequestFactory;
    private UaaAuthorizationEndpoint uaaAuthorizationEndpoint;
    private AuthorizationCodeServices authorizationCodeServices;
    private Set<String> responseTypes;

    @Before
    public void setup() {
        oAuth2RequestFactory = mock(OAuth2RequestFactory.class);
        uaaAuthorizationEndpoint = new UaaAuthorizationEndpoint();
        uaaAuthorizationEndpoint.setOAuth2RequestFactory(oAuth2RequestFactory);
        authorizationCodeServices = mock(AuthorizationCodeServices.class);
        uaaAuthorizationEndpoint.setAuthorizationCodeServices(authorizationCodeServices);
        responseTypes = new HashSet<>();
    }


    @Test
    public void testGetGrantType_id_token_only_is_implicit() {
        responseTypes.add("id_token");
        assertEquals("implicit", uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_token_as_response_is_implcit() {
        responseTypes.add("token");
        assertEquals("implicit", uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_code_is_auth_code() {
        responseTypes.add("code");
        assertEquals("authorization_code", uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_code_and_token_is_implicit() {
        responseTypes.add("code");
        responseTypes.add("token");
        assertEquals("implicit", uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_id_token_and_token_is_implicit() {
        responseTypes.add("id_token");
        responseTypes.add("token");
        assertEquals("implicit", uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_code_and_id_token_is_authorization_code() {
        responseTypes.add("code");
        responseTypes.add("id_token");
        assertEquals("authorization_code", uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_code_id_token_and_token_is_implicit() {
        responseTypes.add("code");
        responseTypes.add("id_token");
        responseTypes.add("token");
        assertEquals("implicit", uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testBuildRedirectURI() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setRedirectUri("example.com");
        authorizationRequest.setResponseTypes(new HashSet<String>() { { add("code"); add("token"); add("id_token"); } } );
        authorizationRequest.setState("California");

        CompositeAccessToken accessToken = new CompositeAccessToken("TOKEN_VALUE+=");
        accessToken.setIdTokenValue("idTokenValue");
        Calendar calendar = Calendar.getInstance();
        calendar.set(2030,1,1);
        accessToken.setExpiration(calendar.getTime());

        UaaPrincipal principal = new UaaPrincipal("userid","username","email","origin","extid","zoneid");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(true, "clientid", "origin", "SOMESESSIONID");
        Authentication authUser = new UaaAuthentication(principal, Collections.emptyList(), details);

        OAuth2Request storedOAuth2Request = mock(OAuth2Request.class);
        when(oAuth2RequestFactory.createOAuth2Request(any())).thenReturn(storedOAuth2Request);

        when(authorizationCodeServices.createAuthorizationCode(any())).thenReturn("ABCD");
        String result = uaaAuthorizationEndpoint.buildRedirectURI(authorizationRequest, accessToken, authUser);

        assertEquals("example.com#token_type=bearer&access_token=TOKEN_VALUE%2B%3D&id_token=idTokenValue&code=ABCD&state=California&expires_in=383183999&scope=null", result);
    }
}