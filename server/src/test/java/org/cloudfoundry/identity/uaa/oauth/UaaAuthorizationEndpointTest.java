package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.PlainPkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.S256PkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.approval.DefaultUserApprovalHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UaaAuthorizationEndpointTest {

    private OAuth2RequestFactory oAuth2RequestFactory;
    private UaaAuthorizationEndpoint uaaAuthorizationEndpoint;
    private AuthorizationCodeServices authorizationCodeServices;
    private Set<String> responseTypes;
    private OpenIdSessionStateCalculator openIdSessionStateCalculator;
    private PkceValidationService pkceValidationService;

    private final HashMap<String, Object> model = new HashMap<>();
    private final SimpleSessionStatus sessionStatus = new SimpleSessionStatus();
    private final UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken("foo", "bar", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

    @BeforeEach
    void setup() {
        oAuth2RequestFactory = mock(OAuth2RequestFactory.class);
        authorizationCodeServices = mock(AuthorizationCodeServices.class);
        openIdSessionStateCalculator = mock(OpenIdSessionStateCalculator.class);

        PlainPkceVerifier plainPkceVerifier = new PlainPkceVerifier();
        S256PkceVerifier s256PkceVerifier = new S256PkceVerifier();
        Map<String, PkceVerifier> pkceVerifiers = new HashMap<>();
        pkceVerifiers.put(plainPkceVerifier.getCodeChallengeMethod(), plainPkceVerifier);
        pkceVerifiers.put(s256PkceVerifier.getCodeChallengeMethod(), s256PkceVerifier);
        pkceValidationService = new PkceValidationService(pkceVerifiers);

        uaaAuthorizationEndpoint = new UaaAuthorizationEndpoint(
                null,
                new DefaultUserApprovalHandler(),
                null,
                authorizationCodeServices,
                null,
                oAuth2RequestFactory,
                null,
                null,
                pkceValidationService);
        uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(openIdSessionStateCalculator);
        responseTypes = new HashSet<>();

        when(openIdSessionStateCalculator.calculate("userid", null, "http://example.com")).thenReturn("opbshash");
        when(authorizationCodeServices.createAuthorizationCode(any(OAuth2Authentication.class))).thenReturn("code");
    }

    @Test
    void getGrantTypeIdTokenOnlyIsImplicit() {
        responseTypes.add("id_token");
        assertThat(uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes)).isEqualTo(GRANT_TYPE_IMPLICIT);
    }

    @Test
    void getGrantTypeTokenAsResponseIsImplcit() {
        responseTypes.add("token");
        assertThat(uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes)).isEqualTo(GRANT_TYPE_IMPLICIT);
    }

    @Test
    void getGrantTypeCodeIsAuthCode() {
        responseTypes.add("code");
        assertThat(uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes)).isEqualTo(GRANT_TYPE_AUTHORIZATION_CODE);
    }

    @Test
    void getGrantTypeCodeAndTokenIsImplicit() {
        responseTypes.add("code");
        responseTypes.add("token");
        assertThat(uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes)).isEqualTo(GRANT_TYPE_IMPLICIT);
    }

    @Test
    void getGrantTypeIdTokenAndTokenIsImplicit() {
        responseTypes.add("id_token");
        responseTypes.add("token");
        assertThat(uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes)).isEqualTo(GRANT_TYPE_IMPLICIT);
    }

    @Test
    void getGrantTypeCodeAndIdTokenIsAuthorizationCode() {
        responseTypes.add("code");
        responseTypes.add("id_token");
        assertThat(uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes)).isEqualTo(GRANT_TYPE_AUTHORIZATION_CODE);
    }

    @Test
    void getGrantTypeCodeIdTokenAndTokenIsImplicit() {
        responseTypes.add("code");
        responseTypes.add("id_token");
        responseTypes.add("token");
        assertThat(uaaAuthorizationEndpoint.deriveGrantTypeFromResponseType(responseTypes)).isEqualTo(GRANT_TYPE_IMPLICIT);
    }

    @Test
    void buildRedirectURIDoesNotIncludeSessionStateWhenNotPromptNone() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setRedirectUri("http://example.com/somepath");
        authorizationRequest.setResponseTypes(new HashSet<>() {
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

        assertThat(result).contains("http://example.com/somepath#")
                .contains("token_type=bearer")
                .contains("access_token=TOKEN_VALUE+%3D")
                .contains("id_token=idTokenValue")
                .contains("code=ABCD")
                .contains("state=California")
                .contains("expires_in=")
                .contains("scope=null");
    }

    @Test
    void buildRedirectURI_includesSessionStateForPromptEqualsNone() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setRedirectUri("http://example.com/somepath");
        authorizationRequest.setRequestParameters(new HashMap<>() {
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

        assertThat(result).contains("session_state=opbshash");
    }

    @Test
    void approveUnmodifiedRequest() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest("foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));

        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");

        when(authorizationCodeServices.createAuthorizationCode(any(OAuth2Authentication.class))).thenReturn("code");

        View view = uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
        assertThat(view).isInstanceOf(RedirectView.class);
        assertThat(((RedirectView) view).getUrl()).doesNotContain("error=invalid_scope");
    }

    @Test
    void approveWithModifiedScope() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setScope(Arrays.asList("read", "write"));
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal));
    }

    @Test
    void approveWithModifiedClientId() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setClientId("bar");
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal));
    }

    @Test
    void approveWithModifiedState() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setState("state-5678");
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal));
    }

    @Test
    void approveWithModifiedRedirectUri() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setRedirectUri("http://somewhere.com");
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal));
    }

    @Test
    void approveWithModifiedResponseTypes() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setResponseTypes(Collections.singleton("implicit"));
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal));
    }

    @Test
    void approveWithModifiedApproved() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        authorizationRequest.setApproved(false);
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setApproved(true);
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal));
    }

    @Test
    void approveWithModifiedResourceIds() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setResourceIds(Collections.singleton("resource-other"));
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal));
    }

    @Test
    void approveWithModifiedAuthorities() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));
        authorizationRequest.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("authority-other"));
        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal));
    }

    @Test
    void approveWithModifiedApprovalParameters() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "http://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        authorizationRequest.setApproved(false);
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        model.put(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, uaaAuthorizationEndpoint.unmodifiableMap(authorizationRequest));

        Map<String, String> approvalParameters = new HashMap<>();
        approvalParameters.put("user_oauth_approval", "true");
        approvalParameters.put("scope.0", "foobar");

        View view = uaaAuthorizationEndpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);

        assertThat(view).isInstanceOf(RedirectView.class);
        assertThat(((RedirectView) view).getUrl()).contains("error=invalid_scope");
    }

    @Test
    void shortCodeChallengeParameter() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put(PkceValidationService.CODE_CHALLENGE, "ShortCodeChallenge");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.validateAuthorizationRequestPkceParameters(parameters));
    }

    @Test
    void longCodeChallengeParameter() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put(PkceValidationService.CODE_CHALLENGE, "LongCodeChallenge12346574382823193700987654321326352173528351287635126532123452534234254323254325325325432342532532254325432532532");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.validateAuthorizationRequestPkceParameters(parameters));
    }

    @Test
    void forbiddenCodeChallengeParameter() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put(PkceValidationService.CODE_CHALLENGE, "#ForbiddenCodeChallenge098765445647544743211234657438282319370#");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.validateAuthorizationRequestPkceParameters(parameters));
    }

    @Test
    void unsupportedCodeChallengeMethodParameter() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put(PkceValidationService.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE);
        parameters.put(PkceValidationService.CODE_CHALLENGE_METHOD, "unsupportedMethod");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                uaaAuthorizationEndpoint.validateAuthorizationRequestPkceParameters(parameters));
    }

    @Test
    void newSetters() {
        uaaAuthorizationEndpoint.setUserApprovalHandler(new DefaultUserApprovalHandler());
        uaaAuthorizationEndpoint.setOAuth2RequestValidator(new UaaOauth2RequestValidator());
        assertThat(uaaAuthorizationEndpoint).isNotNull();
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
        return new AuthorizationRequest(parameters, parameters.get(OAuth2Utils.CLIENT_ID),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)), null, null, false,
                parameters.get(OAuth2Utils.STATE), parameters.get(OAuth2Utils.REDIRECT_URI),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.RESPONSE_TYPE)));
    }
}
