package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.PlainPkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.S256PkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.web.bind.support.SimpleSessionStatus;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UaaAuthorizationEndpointTest {

    private OAuth2RequestFactory oAuth2RequestFactory;
    private UaaAuthorizationEndpoint uaaAuthorizationEndpoint;
    private AuthorizationCodeServices authorizationCodeServices;
    private Set<String> responseTypes;
    private OpenIdSessionStateCalculator openIdSessionStateCalculator;
    private PkceValidationService pkceValidationService;

    private HashMap<String, Object> model = new HashMap<>();
    private SimpleSessionStatus sessionStatus = new SimpleSessionStatus();
    private UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken("foo", "bar", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

    @Before
    public void setup() {
        oAuth2RequestFactory = mock(OAuth2RequestFactory.class);
        authorizationCodeServices = mock(AuthorizationCodeServices.class);
        openIdSessionStateCalculator = mock(OpenIdSessionStateCalculator.class);

        PlainPkceVerifier plainPkceVerifier = new PlainPkceVerifier();
        S256PkceVerifier s256PkceVerifier = new S256PkceVerifier();
        Map<String,PkceVerifier> pkceVerifiers = new HashMap<String,PkceVerifier>();
        pkceVerifiers.put(plainPkceVerifier.getCodeChallengeMethod(), plainPkceVerifier);
        pkceVerifiers.put(s256PkceVerifier.getCodeChallengeMethod(), s256PkceVerifier);
        pkceValidationService = new PkceValidationService(pkceVerifiers);

        uaaAuthorizationEndpoint = new UaaAuthorizationEndpoint(
                null,
                new DefaultUserApprovalHandler(),
                null,
                authorizationCodeServices,
                null,
                openIdSessionStateCalculator,
                oAuth2RequestFactory,
                null,
                null,
                pkceValidationService);
        responseTypes = new HashSet<>();

        when(openIdSessionStateCalculator.calculate("userid", null, "http://example.com")).thenReturn("opbshash");
        when(authorizationCodeServices.createAuthorizationCode(any(OAuth2Authentication.class))).thenReturn("code");
    }

    @Test
    public void testGetGrantType_id_token_only_is_implicit() {
        responseTypes.add("id_token");
        assertEquals(GRANT_TYPE_IMPLICIT, uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_token_as_response_is_implcit() {
        responseTypes.add("token");
        assertEquals(GRANT_TYPE_IMPLICIT, uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_code_is_auth_code() {
        responseTypes.add("code");
        assertEquals(GRANT_TYPE_AUTHORIZATION_CODE, uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_code_and_token_is_implicit() {
        responseTypes.add("code");
        responseTypes.add("token");
        assertEquals(GRANT_TYPE_IMPLICIT, uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_id_token_and_token_is_implicit() {
        responseTypes.add("id_token");
        responseTypes.add("token");
        assertEquals(GRANT_TYPE_IMPLICIT, uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_code_and_id_token_is_authorization_code() {
        responseTypes.add("code");
        responseTypes.add("id_token");
        assertEquals(GRANT_TYPE_AUTHORIZATION_CODE, uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testGetGrantType_code_id_token_and_token_is_implicit() {
        responseTypes.add("code");
        responseTypes.add("id_token");
        responseTypes.add("token");
        assertEquals(GRANT_TYPE_IMPLICIT, uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes));
    }

    @Test
    public void testBuildRedirectURI_doesNotIncludeSessionStateWhenNotPromptNone() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setRedirectUri("http://example.com/somepath");
        authorizationRequest.setResponseTypes(new HashSet<String>() {
            {
                add("code");
                add("token");
                add("id_token");
            }
        });
        authorizationRequest.setState("California");
        CompositeToken accessToken = new CompositeToken("TOKEN_VALUE+=");
        accessToken.setIdTokenValue("idTokenValue");
        UaaPrincipal principal = new UaaPrincipal("userid", "username", "email", "origin", "extid", "zoneid");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(true, "clientid", "origin", "SOMESESSIONID");
        Authentication authUser = new UaaAuthentication(principal, Collections.emptyList(), details);
        accessToken.setExpiration(Calendar.getInstance().getTime());
        OAuth2Request storedOAuth2Request = mock(OAuth2Request.class);
        when(oAuth2RequestFactory.createOAuth2Request(any())).thenReturn(storedOAuth2Request);
        when(authorizationCodeServices.createAuthorizationCode(any())).thenReturn("ABCD");

        String result = uaaAuthorizationEndpoint.buildRedirectURI(authorizationRequest, accessToken, authUser);

        assertThat(result, containsString("http://example.com/somepath#"));
        assertThat(result, containsString("token_type=bearer"));
        assertThat(result, containsString("access_token=TOKEN_VALUE+%3D"));
        assertThat(result, containsString("id_token=idTokenValue"));
        assertThat(result, containsString("code=ABCD"));
        assertThat(result, containsString("state=California"));
        assertThat(result, containsString("expires_in="));
        assertThat(result, containsString("scope=null"));
    }

    @Test
    public void buildRedirectURI_includesSessionStateForPromptEqualsNone() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setRedirectUri("http://example.com/somepath");
        authorizationRequest.setRequestParameters(new HashMap<String, String>() {
            {
                put("prompt", "none");
            }
        });
        CompositeToken accessToken = new CompositeToken("TOKEN_VALUE+=");
        UaaPrincipal principal = new UaaPrincipal("userid", "username", "email", "origin", "extid", "zoneid");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(true, "clientid", "origin", "SOMESESSIONID");
        Authentication authUser = new UaaAuthentication(principal, Collections.emptyList(), details);
        when(authorizationCodeServices.createAuthorizationCode(any())).thenReturn("ABCD");

        String result = uaaAuthorizationEndpoint.buildRedirectURI(authorizationRequest, accessToken, authUser);

        assertThat(result, containsString("session_state=opbshash"));
    }

    @Test
    public void approveUnmodifiedRequest() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));

        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");

        when(authorizationCodeServices.createAuthorizationCode(any(OAuth2Authentication.class))).thenReturn("code");

        View view = uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        assertThat(view, notNullValue());
        assertThat(view, instanceOf(RedirectView.class));
        assertThat(((RedirectView) view).getUrl(), not(containsString("error=invalid_scope")));
    }

    @Test(expected = InvalidRequestException.class)
    public void testApproveWithModifiedScope() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));

        authorizationRequest.setScope(Arrays.asList("read", "write"));        // Modify authorization request
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");

        uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
    }

    @Test(expected = InvalidRequestException.class)
    public void testApproveWithModifiedClientId() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setClientId("bar");        // Modify authorization request
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");

        uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
    }

    @Test(expected = InvalidRequestException.class)
    public void testApproveWithModifiedState() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setState("state-5678");        // Modify authorization request
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");

        uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
    }

    @Test(expected = InvalidRequestException.class)
    public void testApproveWithModifiedRedirectUri() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setRedirectUri("http://somewhere.com");        // Modify authorization request
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");

        uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
    }

    @Test(expected = InvalidRequestException.class)
    public void testApproveWithModifiedResponseTypes() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setResponseTypes(Collections.singleton("implicit"));        // Modify authorization request
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");

        uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
    }

    @Test(expected = InvalidRequestException.class)
    public void testApproveWithModifiedApproved() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        authorizationRequest.setApproved(false);
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setApproved(true);        // Modify authorization request
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");

        uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
    }

    @Test(expected = InvalidRequestException.class)
    public void testApproveWithModifiedResourceIds() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setResourceIds(Collections.singleton("resource-other"));        // Modify authorization request
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");

        uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
    }

    @Test(expected = InvalidRequestException.class)
    public void testApproveWithModifiedAuthorities() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("authority-other"));        // Modify authorization request
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");

        uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
    }

    @Test
    public void testApproveWithModifiedApprovalParameters() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        authorizationRequest.setApproved(false);
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));

        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");
        approvalParameters.put("scope.0", "foobar");

        View view = uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);

        assertThat(view, instanceOf(RedirectView.class));
        assertThat(((RedirectView) view).getUrl(), containsString("error=invalid_scope"));
    }

    @Test(expected = InvalidRequestException.class)
    public void testShortCodeChallengeParameter() throws Exception {
    	Map<String, String> parameters = new HashMap<String, String>();
    	parameters.put(PkceValidationService.CODE_CHALLENGE, "ShortCodeChallenge");
    	uaaAuthorizationEndpoint.validateAuthorizationRequestPkceParameters(parameters);
    }
    
    @Test(expected = InvalidRequestException.class)
    public void testLongCodeChallengeParameter() throws Exception {
    	Map<String, String> parameters = new HashMap<String, String>();
    	parameters.put(PkceValidationService.CODE_CHALLENGE, "LongCodeChallenge12346574382823193700987654321326352173528351287635126532123452534234254323254325325325432342532532254325432532532");
    	uaaAuthorizationEndpoint.validateAuthorizationRequestPkceParameters(parameters);
    }
    
    @Test(expected = InvalidRequestException.class)
    public void testForbiddenCodeChallengeParameter() throws Exception {
    	Map<String, String> parameters = new HashMap<String, String>();
    	parameters.put(PkceValidationService.CODE_CHALLENGE, "#ForbiddenCodeChallenge098765445647544743211234657438282319370#");
    	uaaAuthorizationEndpoint.validateAuthorizationRequestPkceParameters(parameters);
    }
    
    @Test(expected = InvalidRequestException.class)
    public void testUnsupportedCodeChallengeMethodParameter() throws Exception {
    	Map<String, String> parameters = new HashMap<String, String>();
    	parameters.put(PkceValidationService.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE);
    	parameters.put(PkceValidationService.CODE_CHALLENGE_METHOD, "unsupportedMethod");
    	uaaAuthorizationEndpoint.validateAuthorizationRequestPkceParameters(parameters);
    }

    private AuthorizationRequest getAuthorizationRequest(String clientId, String redirectUri, String state,
                                                         String scope, Set<String> responseTypes) {
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put(OAuth2Utils.CLIENT_ID, clientId);
        if (redirectUri != null) {
            parameters.put(OAuth2Utils.REDIRECT_URI, redirectUri);
        }
        if (state != null) {
            parameters.put(OAuth2Utils.STATE, state);
        }
        if (scope != null) {
            parameters.put(OAuth2Utils.SCOPE, scope);
        }
        if (responseTypes != null) {
            parameters.put(OAuth2Utils.RESPONSE_TYPE, OAuth2Utils.formatParameterList(responseTypes));
        }
        return new AuthorizationRequest(parameters, Collections.emptyMap(),
                parameters.get(OAuth2Utils.CLIENT_ID),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)), null, null, false,
                parameters.get(OAuth2Utils.STATE), parameters.get(OAuth2Utils.REDIRECT_URI),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.RESPONSE_TYPE)));
    }
}
