package org.cloudfoundry.identity.uaa.oauth;
import org.apache.hc.client5.http.utils.URIUtils;
import org.apache.hc.core5.http.HttpHost;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.approval.UserApprovalHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitGrantService;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.AbstractEndpoint;
import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.BadClientCredentialsException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.ClientAuthenticationException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnapprovedClientAuthenticationException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnauthorizedClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnsupportedResponseTypeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UserDeniedAuthorizationException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.RedirectResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.HttpSessionRequiredException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.DefaultSessionAttributeStore;
import org.springframework.web.bind.support.SessionAttributeStore;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Arrays.stream;
import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.hasText;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addFragmentComponent;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addQueryParameter;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.SCOPE_PREFIX;

/**
 * Authorization endpoint that returns id_token's if requested.
 * This is a copy of AuthorizationEndpoint.java in
 * Spring Security Oauth2. As that code does not allow
 * for redirect responses to be customized, as desired by
 * https://github.com/fhanik/spring-security-oauth/compare/feature/extendable-redirect-generator?expand=1
 */
@Controller
@SessionAttributes({
        UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST,
        UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST
})
public class UaaAuthorizationEndpoint extends AbstractEndpoint implements AuthenticationEntryPoint {
    // matches org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTR_NAME
    public static final String AUTHORIZATION_REQUEST = "authorizationRequest";
    // matching org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME
    public static final String ORIGINAL_AUTHORIZATION_REQUEST = "org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST";
    private static final String userApprovalPage = "forward:/oauth/confirm_access";
    private static final String errorPage = "forward:/oauth/error";
    private static final List<String> supported_response_types = Arrays.asList("code", "token", "id_token");

    private final RedirectResolver redirectResolver;
    private UserApprovalHandler userApprovalHandler;
    private OAuth2RequestValidator oauth2RequestValidator;
    private final AuthorizationCodeServices authorizationCodeServices;
    private final HybridTokenGranterForAuthorizationCode hybridTokenGranterForAuthCode;
    private OpenIdSessionStateCalculator openIdSessionStateCalculator = new OpenIdSessionStateCalculator();

    private final SessionAttributeStore sessionAttributeStore;
    private final Object implicitLock;
    private final PkceValidationService pkceValidationService;

    /**
     * @param tokenGranter created by <oauth:authorization-server/>
     */
    public UaaAuthorizationEndpoint(
            final RedirectResolver redirectResolver,
            final @Qualifier("userManagedApprovalHandler") UserApprovalHandler userApprovalHandler,
            final @Qualifier("oauth2RequestValidator") OAuth2RequestValidator oauth2RequestValidator,
            final @Qualifier("authorizationCodeServices") AuthorizationCodeServices authorizationCodeServices,
            final @Qualifier("hybridTokenGranterForAuthCodeGrant") HybridTokenGranterForAuthorizationCode hybridTokenGranterForAuthCode,
            final @Qualifier("authorizationRequestManager") OAuth2RequestFactory oAuth2RequestFactory,
            final @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            final @Qualifier("oauth2TokenGranter") TokenGranter tokenGranter,
            final @Qualifier("pkceValidationServices") PkceValidationService pkceValidationService) {
        this.redirectResolver = redirectResolver;
        this.userApprovalHandler = userApprovalHandler;
        this.oauth2RequestValidator = oauth2RequestValidator;
        this.authorizationCodeServices = authorizationCodeServices;
        this.hybridTokenGranterForAuthCode = hybridTokenGranterForAuthCode;
        this.pkceValidationService = pkceValidationService;

        super.setOAuth2RequestFactory(oAuth2RequestFactory);
        super.setClientDetailsService(clientDetailsService);
        super.setTokenGranter(tokenGranter);

        this.sessionAttributeStore = new DefaultSessionAttributeStore();
        this.implicitLock = new Object();
    }

    @RequestMapping(value = "/oauth/authorize")
    public ModelAndView authorize(Map<String, Object> model,
            @RequestParam Map<String, String> parameters,
            SessionStatus sessionStatus,
            Principal principal,
            HttpServletRequest request) {

        ClientDetails client;
        String clientId;
        try {
            clientId = parameters.get("client_id");
            client = loadClientByClientId(clientId);
        } catch (NoSuchClientException x) {
            throw new InvalidClientException(x.getMessage());
        }

        // Pull out the authorization request first, using the OAuth2RequestFactory. All further logic should
        // query off of the authorization request instead of referring back to the parameters map. The contents of the
        // parameters map will be stored without change in the AuthorizationRequest object once it is created.
        AuthorizationRequest authorizationRequest;
        try {
            authorizationRequest = getOAuth2RequestFactory().createAuthorizationRequest(parameters);
        } catch (DisallowedIdpException x) {
            return switchIdp(model, client, clientId, request);
        }

        Set<String> responseTypes = authorizationRequest.getResponseTypes();
        String grantType = deriveGrantTypeFromResponseType(responseTypes);

        if (!supported_response_types.containsAll(responseTypes)) {
            throw new UnsupportedResponseTypeException("Unsupported response types");
        }

        if (authorizationRequest.getClientId() == null) {
            throw new InvalidClientException("A client id must be provided");
        }

        validateAuthorizationRequestPkceParameters(authorizationRequest.getRequestParameters());

        String resolvedRedirect = "";
        try {
            String redirectUriParameter = authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI);
            try {
                resolvedRedirect = redirectResolver.resolveRedirect(redirectUriParameter, client);
            } catch (RedirectMismatchException rme) {
                throw new RedirectMismatchException(
                        "Invalid redirect " + redirectUriParameter + " did not match one of the registered values");
            }
            if (!StringUtils.hasText(resolvedRedirect)) {
                throw new RedirectMismatchException(
                        "A redirectUri must be either supplied or preconfigured in the ClientDetails");
            }

            boolean isAuthenticated = (principal instanceof Authentication a) && a.isAuthenticated();

            if (!isAuthenticated) {
                throw new InsufficientAuthenticationException(
                        "User must be authenticated with Spring Security before authorization can be completed.");
            }

            if (responseTypes.size() <= 0) {
                return new ModelAndView(new RedirectView(addQueryParameter(addQueryParameter(resolvedRedirect, "error", "invalid_request"), "error_description", "Missing response_type in authorization request")));
            }

            authorizationRequest.setRedirectUri(resolvedRedirect);
            // We intentionally only validate the parameters requested by the client (ignoring any data that may have
            // been added to the request by the manager).
            oauth2RequestValidator.validateScope(authorizationRequest, client);

            // Some systems may allow for approval decisions to be remembered or approved by default. Check for
            // such logic here, and set the approved flag on the authorization request accordingly.
            authorizationRequest = userApprovalHandler.checkForPreApproval(authorizationRequest,
                    (Authentication) principal);
            boolean approved = userApprovalHandler.isApproved(authorizationRequest, (Authentication) principal);
            authorizationRequest.setApproved(approved);

            // Validation is all done, so we can check for auto approval...
            if (authorizationRequest.isApproved()) {
                if (responseTypes.contains("token") || responseTypes.contains("id_token")) {
                    return getImplicitGrantOrHybridResponse(
                            authorizationRequest,
                            (Authentication) principal,
                            grantType
                    );
                }
                if (responseTypes.contains("code")) {
                    return new ModelAndView(getAuthorizationCodeResponse(authorizationRequest,
                            (Authentication) principal));
                }
            }


            if ("none".equals(authorizationRequest.getRequestParameters().get("prompt"))) {
                return new ModelAndView(
                        new RedirectView(addFragmentComponent(resolvedRedirect, "error=interaction_required"))
                );
            } else {
                // Place auth request into the model so that it is stored in the session
                // for approveOrDeny to use. That way we make sure that auth request comes from the session,
                // so any auth request parameters passed to approveOrDeny will be ignored and retrieved from the session.
                model.put(AUTHORIZATION_REQUEST, authorizationRequest);
                model.put("original_uri", UrlUtils.buildFullRequestUrl(request));
                model.put(ORIGINAL_AUTHORIZATION_REQUEST, unmodifiableMap(authorizationRequest));
                // skip CSRF check for the authorize endpoint and internal forward to the user approval page
                if (request.getServletPath().endsWith("/oauth/authorize")) {
                    CsrfFilter.skipRequest(request);
                }
                return getUserApprovalPageResponse(model, authorizationRequest, (Authentication) principal);
            }
        } catch (RedirectMismatchException e) {
            sessionStatus.setComplete();
            throw e;
        } catch (Exception e) {
            sessionStatus.setComplete();
            logger.debug("Unable to handle /oauth/authorize, internal error", e);
            if ("none".equals(authorizationRequest.getRequestParameters().get("prompt"))) {
                return new ModelAndView(
                        new RedirectView(addFragmentComponent(resolvedRedirect, "error=internal_server_error"))
                );
            }

            throw e;
        }

    }

    /**
     * PKCE parameters check: 
     *      code_challenge: (Optional) Must be provided for PKCE and must not be empty.
     *      code_challenge_method: (Optional) Default value is "plain". See .well-known 
     *                             endpoint for supported code challenge methods list.  
     * @param authorizationRequestParameters Authorization request parameters.
     */
    protected void validateAuthorizationRequestPkceParameters(Map<String, String> authorizationRequestParameters) {
        if (pkceValidationService != null) {
            String codeChallenge = authorizationRequestParameters.get(PkceValidationService.CODE_CHALLENGE);
            if (codeChallenge != null) {
                if (!PkceValidationService.isCodeChallengeParameterValid(codeChallenge)) {
                    throw new InvalidRequestException("Code challenge length must between 43 and 128 and use only [A-Z],[a-z],[0-9],_,.,-,~ characters.");
                }
                String codeChallengeMethod = authorizationRequestParameters.get(PkceValidationService.CODE_CHALLENGE_METHOD);
                if (codeChallengeMethod == null) {
                    codeChallengeMethod = "plain";
                }
                if (!pkceValidationService.isCodeChallengeMethodSupported(codeChallengeMethod)) {
                    throw new InvalidRequestException("Unsupported code challenge method. Supported: " +
                            pkceValidationService.getSupportedCodeChallengeMethods().toString());
                }
            }
        }
    }

    // This method handles /oauth/authorize calls when user is not logged in and the prompt=none param is used
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        String clientId = request.getParameter(OAuth2Utils.CLIENT_ID);
        String redirectUri = request.getParameter(OAuth2Utils.REDIRECT_URI);
        String[] responseTypes = ofNullable(request.getParameter(OAuth2Utils.RESPONSE_TYPE)).map(rt -> rt.split(" ")).orElse(new String[0]);

        ClientDetails client;
        try {
            client = loadClientByClientId(clientId);
        } catch (ClientRegistrationException e) {
            logger.debug("[prompt=none] Unable to look up client for client_id=" + clientId, e);
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }

        Set<String> redirectUris = ofNullable(client.getRegisteredRedirectUri()).orElse(emptySet());

        //if the client doesn't have a redirect uri set, the parameter is required.
        if (redirectUris.isEmpty() && !hasText(redirectUri)) {
            logger.debug("[prompt=none] Missing redirect_uri");
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }

        String resolvedRedirect;
        try {
            resolvedRedirect = redirectResolver.resolveRedirect(redirectUri, client);
        } catch (RedirectMismatchException rme) {
            logger.debug("[prompt=none] Invalid redirect " + redirectUri + " did not match one of the registered values");
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }

        HttpHost httpHost = URIUtils.extractHost(URI.create(resolvedRedirect));
        String sessionState = openIdSessionStateCalculator.calculate("", clientId, httpHost.toURI());
        boolean implicit = stream(responseTypes).noneMatch("code"::equalsIgnoreCase);
        String redirectLocation;
        String errorCode = authException instanceof InteractionRequiredException ? "interaction_required" : "login_required";
        if (implicit) {
            redirectLocation = addFragmentComponent(resolvedRedirect, "error=" + errorCode);
            redirectLocation = addFragmentComponent(redirectLocation, "session_state=" + sessionState);
        } else {
            redirectLocation = addQueryParameter(resolvedRedirect, "error", errorCode);
            redirectLocation = addQueryParameter(redirectLocation, "session_state", sessionState);
        }

        response.sendRedirect(redirectLocation);
    }

    private ModelAndView switchIdp(Map<String, Object> model, ClientDetails client, String clientId, HttpServletRequest request) {
        Map<String, Object> additionalInfo = client.getAdditionalInformation();
        String clientDisplayName = (String) additionalInfo.get(ClientConstants.CLIENT_NAME);
        model.put("client_display_name", clientDisplayName != null ? clientDisplayName : clientId);

        String queryString = UaaHttpRequestUtils.paramsToQueryString(request.getParameterMap());
        String redirectUri = request.getRequestURL() + "?" + queryString;
        model.put("redirect", redirectUri);

        model.put("error", "The application is not authorized for your account.");
        model.put("error_message_code", "login.invalid_idp");

        return new ModelAndView("switch_idp", model, HttpStatus.UNAUTHORIZED);
    }

    Map<String, Object> unmodifiableMap(AuthorizationRequest authorizationRequest) {
        Map<String, Object> authorizationRequestMap = new HashMap<>();

        authorizationRequestMap.put(OAuth2Utils.CLIENT_ID, authorizationRequest.getClientId());
        authorizationRequestMap.put(OAuth2Utils.STATE, authorizationRequest.getState());
        authorizationRequestMap.put(OAuth2Utils.REDIRECT_URI, authorizationRequest.getRedirectUri());

        if (authorizationRequest.getResponseTypes() != null) {
            authorizationRequestMap.put(OAuth2Utils.RESPONSE_TYPE,
                    Set.copyOf(authorizationRequest.getResponseTypes()));
        }
        if (authorizationRequest.getScope() != null) {
            authorizationRequestMap.put(OAuth2Utils.SCOPE,
                    Set.copyOf(authorizationRequest.getScope()));
        }

        authorizationRequestMap.put("approved", authorizationRequest.isApproved());

        if (authorizationRequest.getResourceIds() != null) {
            authorizationRequestMap.put("resourceIds",
                    Set.copyOf(authorizationRequest.getResourceIds()));
        }
        if (authorizationRequest.getAuthorities() != null) {
            authorizationRequestMap.put("authorities",
                    Set.<GrantedAuthority>copyOf(authorizationRequest.getAuthorities()));
        }

        return authorizationRequestMap;
    }

    @PostMapping(value = "/oauth/authorize", params = OAuth2Utils.USER_OAUTH_APPROVAL)
    public View approveOrDeny(@RequestParam Map<String, String> approvalParameters, Map<String, ?> model,
            SessionStatus sessionStatus, Principal principal) {

        if (!(principal instanceof Authentication)) {
            sessionStatus.setComplete();
            throw new InsufficientAuthenticationException(
                    "User must be authenticated with Spring Security before authorizing an access token.");
        }

        AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get(AUTHORIZATION_REQUEST);

        if (authorizationRequest == null) {
            sessionStatus.setComplete();
            throw new InvalidRequestException("Cannot approve uninitialized authorization request.");
        }

        // Check to ensure the Authorization Request was not modified during the user approval step
        @SuppressWarnings("unchecked")
        Map<String, Object> originalAuthorizationRequest = (Map<String, Object>) model.get(ORIGINAL_AUTHORIZATION_REQUEST);
        if (isAuthorizationRequestModified(authorizationRequest, originalAuthorizationRequest)) {
            logger.warn("The requested scopes are invalid");
            throw new InvalidRequestException("Changes were detected from the original authorization request.");
        }

        for (String approvalParameter : approvalParameters.keySet()) {
            if (approvalParameter.startsWith(SCOPE_PREFIX)) {
                String scope = approvalParameters.get(approvalParameter).substring(SCOPE_PREFIX.length());
                Set<String> originalScopes = (Set<String>) originalAuthorizationRequest.get("scope");
                if (!originalScopes.contains(scope)) {
                    sessionStatus.setComplete();

                    logger.warn("The requested scopes are invalid");
                    return new RedirectView(getUnsuccessfulRedirect(authorizationRequest,
                            new InvalidScopeException("The requested scopes are invalid. Please use valid scope names in the request."), false), false, true, false);
                }
            }
        }

        try {
            Set<String> responseTypes = authorizationRequest.getResponseTypes();
            String grantType = deriveGrantTypeFromResponseType(responseTypes);

            authorizationRequest.setApprovalParameters(approvalParameters);
            authorizationRequest = userApprovalHandler.updateAfterApproval(authorizationRequest,
                    (Authentication) principal);
            boolean approved = userApprovalHandler.isApproved(authorizationRequest, (Authentication) principal);
            authorizationRequest.setApproved(approved);

            if (authorizationRequest.getRedirectUri() == null) {
                sessionStatus.setComplete();
                throw new InvalidRequestException("Cannot approve request when no redirect URI is provided.");
            }

            if (!authorizationRequest.isApproved()) {
                return new RedirectView(getUnsuccessfulRedirect(authorizationRequest,
                        new UserDeniedAuthorizationException("User denied access"), responseTypes.contains("token")),
                        false, true, false);
            }

            if (responseTypes.contains("token") || responseTypes.contains("id_token")) {
                return getImplicitGrantOrHybridResponse(
                        authorizationRequest,
                        (Authentication) principal,
                        grantType
                ).getView();
            }

            return getAuthorizationCodeResponse(authorizationRequest, (Authentication) principal);
        } finally {
            sessionStatus.setComplete();
        }

    }

    private boolean isAuthorizationRequestModified(AuthorizationRequest authorizationRequest, Map<String, Object> originalAuthorizationRequest) {
        if (!ObjectUtils.nullSafeEquals(
                authorizationRequest.getClientId(),
                originalAuthorizationRequest.get(OAuth2Utils.CLIENT_ID))) {
            return true;
        }
        if (!ObjectUtils.nullSafeEquals(
                authorizationRequest.getState(),
                originalAuthorizationRequest.get(OAuth2Utils.STATE))) {
            return true;
        }
        if (!ObjectUtils.nullSafeEquals(
                authorizationRequest.getRedirectUri(),
                originalAuthorizationRequest.get(OAuth2Utils.REDIRECT_URI))) {
            return true;
        }
        if (!ObjectUtils.nullSafeEquals(
                authorizationRequest.getResponseTypes(),
                originalAuthorizationRequest.get(OAuth2Utils.RESPONSE_TYPE))) {
            return true;
        }
        if (!ObjectUtils.nullSafeEquals(
                authorizationRequest.isApproved(),
                originalAuthorizationRequest.get("approved"))) {
            return true;
        }
        if (!ObjectUtils.nullSafeEquals(
                authorizationRequest.getResourceIds(),
                originalAuthorizationRequest.get("resourceIds"))) {
            return true;
        }
        if (!ObjectUtils.nullSafeEquals(
                authorizationRequest.getAuthorities(),
                originalAuthorizationRequest.get("authorities"))) {
            return true;
        }

        return !ObjectUtils.nullSafeEquals(
                authorizationRequest.getScope(),
                originalAuthorizationRequest.get(OAuth2Utils.SCOPE));
    }

    protected String deriveGrantTypeFromResponseType(Set<String> responseTypes) {
        if (responseTypes.contains("token")) {
            return GRANT_TYPE_IMPLICIT;
        } else if (responseTypes.size() == 1 && responseTypes.contains("id_token")) {
            return GRANT_TYPE_IMPLICIT;
        }
        return GRANT_TYPE_AUTHORIZATION_CODE;
    }

    // We need explicit approval from the user.
    private ModelAndView getUserApprovalPageResponse(Map<String, Object> model,
            AuthorizationRequest authorizationRequest, Authentication principal) {
        logger.debug("Loading user approval page: " + userApprovalPage);
        model.putAll(userApprovalHandler.getUserApprovalRequest(authorizationRequest, principal));
        return new ModelAndView(userApprovalPage, model);
    }

    // We can grant a token and return it with implicit approval.
    private ModelAndView getImplicitGrantOrHybridResponse(
            AuthorizationRequest authorizationRequest,
            Authentication authentication,
            String grantType
    ) {
        OAuth2AccessToken accessToken;
        try {
            TokenRequest tokenRequest = getOAuth2RequestFactory().createTokenRequest(authorizationRequest, GRANT_TYPE_IMPLICIT);
            Map<String, String> requestParameters = new HashMap<>(authorizationRequest.getRequestParameters());
            requestParameters.put(GRANT_TYPE, grantType);
            authorizationRequest.setRequestParameters(requestParameters);
            OAuth2Request storedOAuth2Request = getOAuth2RequestFactory().createOAuth2Request(authorizationRequest);
            accessToken = getAccessTokenForImplicitGrantOrHybrid(tokenRequest, storedOAuth2Request, grantType);
            if (accessToken == null) {
                throw new UnsupportedResponseTypeException("Unsupported response type: token or id_token");
            }
            return new ModelAndView(
                    new RedirectView(
                            buildRedirectURI(authorizationRequest, accessToken, authentication),
                            false,
                            true,
                            false
                    )
            );
        } catch (OAuth2Exception e) {
            return new ModelAndView(new RedirectView(getUnsuccessfulRedirect(authorizationRequest, e, true), false,
                    true, false));
        }
    }

    private OAuth2AccessToken getAccessTokenForImplicitGrantOrHybrid(TokenRequest tokenRequest,
            OAuth2Request storedOAuth2Request,
            String grantType
    ) throws OAuth2Exception {
        // These 1 method calls have to be atomic, otherwise the ImplicitGrantService can have a race condition where
        // one thread removes the token request before another has a chance to redeem it.
        synchronized (this.implicitLock) {
            switch (grantType) {
                case GRANT_TYPE_IMPLICIT:
                    return getTokenGranter().grant(grantType, new ImplicitTokenRequest(tokenRequest, storedOAuth2Request));
                case GRANT_TYPE_AUTHORIZATION_CODE:
                    return hybridTokenGranterForAuthCode.grant(grantType, new ImplicitTokenRequest(tokenRequest, storedOAuth2Request));
                default:
                    throw new OAuth2Exception(OAuth2Exception.INVALID_GRANT);
            }
        }
    }

    private View getAuthorizationCodeResponse(AuthorizationRequest authorizationRequest, Authentication authUser) {
        try {
            return new RedirectView(
                    getSuccessfulRedirect(
                            authorizationRequest,
                            generateCode(authorizationRequest, authUser)
                    ),
                    false,
                    false, //so that we send absolute URLs always
                    false
            ) {
                @Override
                protected HttpStatus getHttp11StatusCode(HttpServletRequest request, HttpServletResponse response, String targetUrl) {
                    return HttpStatus.FOUND; //Override code, defaults to 303
                }
            };
        } catch (OAuth2Exception e) {
            return new RedirectView(getUnsuccessfulRedirect(authorizationRequest, e, false), false, true, false);
        }
    }

    public String buildRedirectURI(AuthorizationRequest authorizationRequest,
            OAuth2AccessToken accessToken,
            Authentication authUser) {

        String requestedRedirect = authorizationRequest.getRedirectUri();
        if (accessToken == null) {
            throw new InvalidRequestException("An implicit grant could not be made");
        }

        StringBuilder url = new StringBuilder();
        url.append("token_type=").append(encode(accessToken.getTokenType()));

        //only append access token if grant_type is implicit
        //or token is part of the response type
        if (authorizationRequest.getResponseTypes().contains("token")) {
            url.append("&access_token=").append(encode(accessToken.getValue()));
        }

        if (accessToken instanceof CompositeToken token &&
                authorizationRequest.getResponseTypes().contains(CompositeToken.ID_TOKEN)) {
            url.append("&").append(CompositeToken.ID_TOKEN).append("=").append(encode(token.getIdTokenValue()));
        }

        if (authorizationRequest.getResponseTypes().contains("code")) {
            String code = generateCode(authorizationRequest, authUser);
            url.append("&code=").append(encode(code));
        }

        String state = authorizationRequest.getState();
        if (state != null) {
            url.append("&state=").append(encode(state));
        }

        Date expiration = accessToken.getExpiration();
        if (expiration != null) {
            long expiresIn = (expiration.getTime() - System.currentTimeMillis()) / 1000;
            url.append("&expires_in=").append(expiresIn);
        }

        String originalScope = authorizationRequest.getRequestParameters().get(OAuth2Utils.SCOPE);
        if (originalScope == null || !OAuth2Utils.parseParameterList(originalScope).equals(accessToken.getScope())) {
            url.append("&" + OAuth2Utils.SCOPE + "=").append(encode(OAuth2Utils.formatParameterList(accessToken.getScope())));
        }

        Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
        for (String key : additionalInformation.keySet()) {
            Object value = additionalInformation.get(key);
            if (value != null) {
                url.append("&").append(encode(key)).append("=").append(encode(value.toString()));
            }
        }


        if ("none".equals(authorizationRequest.getRequestParameters().get("prompt"))) {
            HttpHost httpHost = URIUtils.extractHost(URI.create(requestedRedirect));
            String sessionState = openIdSessionStateCalculator.calculate(((UaaPrincipal) authUser.getPrincipal()).getId(),
                    authorizationRequest.getClientId(), httpHost.toURI());

            url.append("&session_state=").append(sessionState);
        }

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(requestedRedirect);
        String existingFragment = builder.build(true).getFragment();
        if (StringUtils.hasText(existingFragment)) {
            existingFragment = existingFragment + "&" + url.toString();
        } else {
            existingFragment = url.toString();
        }
        builder.fragment(existingFragment);
        // Do not include the refresh token (even if there is one)
        return builder.build(true).toUriString();
    }

    private String generateCode(AuthorizationRequest authorizationRequest, Authentication authentication)
            throws AuthenticationException {

        try {

            OAuth2Request storedOAuth2Request = getOAuth2RequestFactory().createOAuth2Request(authorizationRequest);

            OAuth2Authentication combinedAuth = new OAuth2Authentication(storedOAuth2Request, authentication);

            return authorizationCodeServices.createAuthorizationCode(combinedAuth);

        } catch (OAuth2Exception e) {

            if (authorizationRequest.getState() != null) {
                e.addAdditionalInformation("state", authorizationRequest.getState());
            }

            throw e;

        }
    }

    private String encode(String value) {
        return UriUtils.encodeQueryParam(value, "UTF-8");
    }

    private String getSuccessfulRedirect(AuthorizationRequest authorizationRequest, String authorizationCode) {

        if (authorizationCode == null) {
            throw new IllegalStateException("No authorization code found in the current request scope.");
        }

        UriComponentsBuilder template = UriComponentsBuilder.fromUriString(authorizationRequest.getRedirectUri());
        template.queryParam("code", encode(authorizationCode));

        String state = authorizationRequest.getState();
        if (state != null) {
            template.queryParam("state", encode(state));
        }

        return template.build(true).toUriString();
    }

    private String getUnsuccessfulRedirect(AuthorizationRequest authorizationRequest, OAuth2Exception failure,
            boolean fragment) {

        if (authorizationRequest == null || authorizationRequest.getRedirectUri() == null) {
            // we have no redirect for the user. very sad.
            throw new UnapprovedClientAuthenticationException("Authorization failure, and no redirect URI.", failure);
        }

        UriComponentsBuilder template = UriComponentsBuilder.fromUriString(authorizationRequest.getRedirectUri());
        StringBuilder values = new StringBuilder();

        values.append("error=").append(encode(failure.getOAuth2ErrorCode()));
        values.append("&error_description=").append(encode(failure.getMessage()));

        if (authorizationRequest.getState() != null) {
            values.append("&state=").append(encode(authorizationRequest.getState()));
        }

        if (failure.getAdditionalInformation() != null) {
            for (Map.Entry<String, String> additionalInfo : failure.getAdditionalInformation().entrySet()) {
                values.append("&").append(encode(additionalInfo.getKey())).append("=").append(encode(additionalInfo.getValue()));
            }
        }

        if (fragment) {
            template.fragment(values.toString());
        } else {
            template.query(values.toString());
        }

        return template.build(true).toUriString();

    }

    @SuppressWarnings("deprecation")
    public void setImplicitGrantService(ImplicitGrantService implicitGrantService) {
    }

    @ExceptionHandler(ClientRegistrationException.class)
    public ModelAndView handleClientRegistrationException(Exception e, ServletWebRequest webRequest) throws Exception {
        logger.info("Handling ClientRegistrationException error: " + e.getMessage());
        return handleException(new BadClientCredentialsException(), webRequest);
    }

    @ExceptionHandler(OAuth2Exception.class)
    public ModelAndView handleOAuth2Exception(OAuth2Exception e, ServletWebRequest webRequest) throws Exception {
        logger.info("Handling OAuth2 error: " + e.getSummary());
        return handleException(e, webRequest);
    }

    @ExceptionHandler(HttpSessionRequiredException.class)
    public ModelAndView handleHttpSessionRequiredException(HttpSessionRequiredException e, ServletWebRequest webRequest)
            throws Exception {
        logger.info("Handling Session required error: " + e.getMessage());
        return handleException(new AccessDeniedException("Could not obtain authorization request from session", e),
                webRequest);
    }

    private ModelAndView handleException(Exception e, ServletWebRequest webRequest) throws Exception {

        ResponseEntity<OAuth2Exception> translate = getExceptionTranslator().translate(e);
        if (webRequest.getResponse() != null) {
            webRequest.getResponse().setStatus(translate.getStatusCode().value());
        }

        if (e instanceof ClientAuthenticationException || e instanceof RedirectMismatchException) {
            Map<String, Object> map = new HashMap<>();
            map.put("error", translate.getBody());
            if (e instanceof UnauthorizedClientException) {
                map.put("error_message_code", "login.invalid_idp");
            }
            return new ModelAndView(errorPage, map);
        }

        AuthorizationRequest authorizationRequest = null;
        try {
            authorizationRequest = getAuthorizationRequestForError(webRequest);
            String requestedRedirectParam = authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI);
            String requestedRedirect =
                    redirectResolver.resolveRedirect(
                            requestedRedirectParam,
                            loadClientByClientId(authorizationRequest.getClientId()));
            authorizationRequest.setRedirectUri(requestedRedirect);
            String redirect = getUnsuccessfulRedirect(authorizationRequest, translate.getBody(), authorizationRequest
                    .getResponseTypes().contains("token"));
            return new ModelAndView(new RedirectView(redirect, false, true, false));
        } catch (OAuth2Exception ex) {
            // If an AuthorizationRequest cannot be created from the incoming parameters it must be
            // an error. OAuth2Exception can be handled this way. Other exceptions will generate a standard 500
            // response.
            return new ModelAndView(errorPage, Collections.singletonMap("error", translate.getBody()));
        }
    }

    private AuthorizationRequest getAuthorizationRequestForError(ServletWebRequest webRequest) {

        // If it's already there then we are in the approveOrDeny phase and we can use the saved request
        AuthorizationRequest authorizationRequest = (AuthorizationRequest) sessionAttributeStore.retrieveAttribute(
                webRequest, AUTHORIZATION_REQUEST);
        if (authorizationRequest != null) {
            return authorizationRequest;
        }

        Map<String, String> parameters = new HashMap<>();
        Map<String, String[]> map = webRequest.getParameterMap();
        for (String key : map.keySet()) {
            String[] values = map.get(key);
            if (values != null && values.length > 0) {
                parameters.put(key, values[0]);
            }
        }

        try {
            return getOAuth2RequestFactory().createAuthorizationRequest(parameters);
        } catch (Exception e) {
            return getDefaultOAuth2RequestFactory().createAuthorizationRequest(parameters);
        }

    }

    private ClientDetails loadClientByClientId(String clientId) {
        return ((MultitenantClientServices) super.getClientDetailsService())
                .loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
    }

    public void setOAuth2RequestValidator(OAuth2RequestValidator oauth2RequestValidator) {
        this.oauth2RequestValidator = oauth2RequestValidator;
    }

    public void setUserApprovalHandler(UserApprovalHandler userApprovalHandler) {
        this.userApprovalHandler = userApprovalHandler;
    }

    public void setOpenIdSessionStateCalculator(OpenIdSessionStateCalculator openIdSessionStateCalculator) {
        this.openIdSessionStateCalculator = openIdSessionStateCalculator;
    }
}
