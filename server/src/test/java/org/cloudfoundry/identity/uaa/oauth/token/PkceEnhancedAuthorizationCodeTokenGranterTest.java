package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationException;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAATest.CLIENT_ID;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atMost;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PkceEnhancedAuthorizationCodeTokenGranterTest {

    private PkceEnhancedAuthorizationCodeTokenGranter granter;
    private AuthorizationServerTokenServices tokenServices;
    private AuthorizationCodeServices authorizationCodeServices;
    private MultitenantClientServices clientDetailsService;
    private OAuth2RequestFactory requestFactory;
    private OAuth2Request oAuth2Request;
    private UaaClientDetails requestingClient;
    private Map<String, String> requestParameters;
    private OAuth2Authentication authentication;
    private TokenRequest tokenRequest;
    private PkceValidationService pkceValidationService;

    @BeforeEach
    void setup() {
        tokenServices = mock(AuthorizationServerTokenServices.class);
        authorizationCodeServices = mock(AuthorizationCodeServices.class);
        clientDetailsService = mock(MultitenantClientServices.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        authentication = mock(OAuth2Authentication.class);
        tokenRequest = mock(TokenRequest.class);
        oAuth2Request = mock(OAuth2Request.class);
        pkceValidationService = mock(PkceValidationService.class);

        granter = new PkceEnhancedAuthorizationCodeTokenGranter(
                tokenServices,
                authorizationCodeServices,
                clientDetailsService,
                requestFactory
        );
        granter.setPkceValidationService(pkceValidationService);
        SecurityContextHolder.getContext().setAuthentication(authentication);


        requestingClient = new UaaClientDetails("requestingId", null, "uaa.user", GRANT_TYPE_AUTHORIZATION_CODE, null);
        when(clientDetailsService.loadClientByClientId(eq(requestingClient.getClientId()), anyString())).thenReturn(requestingClient);
        when(authorizationCodeServices.consumeAuthorizationCode("1234")).thenReturn(authentication);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        requestParameters = new HashMap<>();
        requestParameters.put(GRANT_TYPE, TokenConstants.GRANT_TYPE_USER_TOKEN);
        requestParameters.put(CLIENT_ID, requestingClient.getClientId());
        requestParameters.put("code", "1234");
        requestParameters.put(PkceValidationService.CODE_VERIFIER, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        when(oAuth2Request.getRequestParameters()).thenReturn(requestParameters);
        tokenRequest = new UserTokenGranterTest.PublicTokenRequest();
        tokenRequest.setRequestParameters(requestParameters);


    }

    @Test
    void getOAuth2Authentication() throws PkceValidationException {
        when(pkceValidationService.checkAndValidate(any(), any(), any())).thenReturn(false);
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() -> granter.getOAuth2Authentication((ClientDetails) requestingClient, tokenRequest));
    }

    @Test
    void getOAuth2AuthenticationMethod() throws PkceValidationException {
        HashMap authMap = new HashMap();
        authMap.put(ClaimConstants.CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE);
        when(pkceValidationService.checkAndValidate(any(), any(), any())).thenReturn(true);
        when(oAuth2Request.getExtensions()).thenReturn(authMap);
        when(oAuth2Request.createOAuth2Request(any())).thenReturn(oAuth2Request);
        assertThat(granter.getOAuth2Authentication((ClientDetails) requestingClient, tokenRequest)).isNotNull();
        verify(oAuth2Request, times(2)).getExtensions();
    }

    @Test
    void getOAuth2AuthenticationNoMethod() throws PkceValidationException {
        HashMap authMap = new HashMap();
        authMap.put(ClaimConstants.CLIENT_AUTH_METHOD, null);
        when(pkceValidationService.checkAndValidate(any(), any(), any())).thenReturn(true);
        when(oAuth2Request.getExtensions()).thenReturn(authMap);
        when(oAuth2Request.createOAuth2Request(any())).thenReturn(oAuth2Request);
        assertThat(granter.getOAuth2Authentication((ClientDetails) requestingClient, tokenRequest)).isNotNull();
        verify(oAuth2Request, atMost(1)).getExtensions();
    }
}