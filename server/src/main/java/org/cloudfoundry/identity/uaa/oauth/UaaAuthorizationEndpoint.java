/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.oauth;

import org.apache.http.HttpHost;
import org.apache.http.client.utils.URIUtils;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.*;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.AbstractEndpoint;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.HttpSessionRequiredException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.Principal;
import java.util.*;

import static java.util.Arrays.stream;
import static java.util.Collections.EMPTY_SET;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.hasText;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addFragmentComponent;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addQueryParameter;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.SCOPE_PREFIX;

/**
 * Authorization endpoint that returns id_token's if requested.
 * This is a copy of AuthorizationEndpoint.java in
 * Spring Security Oauth2. As that code does not allow
 * for redirect responses to be customized, as desired by
 * https://github.com/fhanik/spring-security-oauth/compare/feature/extendable-redirect-generator?expand=1
 */
@Controller
@SessionAttributes({UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST})
public class UaaAuthorizationEndpoint extends AbstractEndpoint implements AuthenticationEntryPoint {

    static final String AUTHORIZATION_REQUEST = "authorizationRequest";
    static final String ORIGINAL_AUTHORIZATION_REQUEST = "org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST";
    private AuthorizationCodeServices authorizationCodeServices = new InMemoryAuthorizationCodeServices();

    private RedirectResolver redirectResolver;

    private UserApprovalHandler userApprovalHandler = new DefaultUserApprovalHandler();

    private SessionAttributeStore sessionAttributeStore = new DefaultSessionAttributeStore();

    private OAuth2RequestValidator oauth2RequestValidator = new DefaultOAuth2RequestValidator();

    private String userApprovalPage = "forward:/oauth/confirm_access";

    private String errorPage = "forward:/oauth/error";

    private Object implicitLock = new Object();

    private HybridTokenGranterForAuthorizationCode hybridTokenGranterForAuthCode;

    private OpenIdSessionStateCalculator openIdSessionStateCalculator;

    private static final List<String> supported_response_types = Arrays.asList("code", "token", "id_token");

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
            client = getClientServiceExtention().loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
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
            throw new UnsupportedResponseTypeException("Unsupported response types: " + responseTypes);
        }

        if (authorizationRequest.getClientId() == null) {
            throw new InvalidClientException("A client id must be provided");
        }

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

            boolean isAuthenticated = (principal instanceof Authentication) && ((Authentication) principal).isAuthenticated();

            if (!isAuthenticated) {
                throw new InsufficientAuthenticationException(
                  "User must be authenticated with Spring Security before authorization can be completed.");
            }

            if (!(responseTypes.size() > 0)) {
                return new ModelAndView(new RedirectView(addQueryParameter(addQueryParameter(resolvedRedirect, "error","invalid_request"), "error_description", "Missing response_type in authorization request")));
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

    // This method handles /oauth/authorize calls when user is not logged in and the prompt=none param is used
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String clientId = request.getParameter(OAuth2Utils.CLIENT_ID);
        String redirectUri = request.getParameter(OAuth2Utils.REDIRECT_URI);
        String[] responseTypes = ofNullable(request.getParameter(OAuth2Utils.RESPONSE_TYPE)).map(rt -> rt.split(" ")).orElse(new String[0]);

        ClientDetails client;
        try {
            client = getClientServiceExtention().loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        } catch (ClientRegistrationException e) {
            logger.debug("[prompt=none] Unable to look up client for client_id=" + clientId, e);
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }

        Set<String> redirectUris = ofNullable(client.getRegisteredRedirectUri()).orElse(EMPTY_SET);

        //if the client doesn't have a redirect uri set, the parameter is required.
        if (redirectUris.size() == 0 && !hasText(redirectUri)) {
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
            redirectLocation = addFragmentComponent(resolvedRedirect, "error="+ errorCode);
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
        model.put("client_display_name", (clientDisplayName != null) ? clientDisplayName : clientId);

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
                    Collections.unmodifiableSet(new HashSet<>(authorizationRequest.getResponseTypes())));
        }
        if (authorizationRequest.getScope() != null) {
            authorizationRequestMap.put(OAuth2Utils.SCOPE,
                    Collections.unmodifiableSet(new HashSet<>(authorizationRequest.getScope())));
        }

        authorizationRequestMap.put("approved", authorizationRequest.isApproved());

        if (authorizationRequest.getResourceIds() != null) {
            authorizationRequestMap.put("resourceIds",
                    Collections.unmodifiableSet(new HashSet<>(authorizationRequest.getResourceIds())));
        }
        if (authorizationRequest.getAuthorities() != null) {
            authorizationRequestMap.put("authorities",
                    Collections.unmodifiableSet(new HashSet<GrantedAuthority>(authorizationRequest.getAuthorities())));
        }

        return authorizationRequestMap;
    }

    @RequestMapping(value = "/oauth/authorize", method = RequestMethod.POST, params = OAuth2Utils.USER_OAUTH_APPROVAL)
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
                    return getHybridTokenGranterForAuthCode().grant(grantType, new ImplicitTokenRequest(tokenRequest, storedOAuth2Request));
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

        if (accessToken instanceof CompositeToken &&
          authorizationRequest.getResponseTypes().contains(CompositeToken.ID_TOKEN)) {
            url.append("&").append(CompositeToken.ID_TOKEN).append("=").append(encode(((CompositeToken) accessToken).getIdTokenValue()));
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
            long expires_in = (expiration.getTime() - System.currentTimeMillis()) / 1000;
            url.append("&expires_in=").append(expires_in);
        }

        String originalScope = authorizationRequest.getRequestParameters().get(OAuth2Utils.SCOPE);
        if (originalScope == null || !OAuth2Utils.parseParameterList(originalScope).equals(accessToken.getScope())) {
            url.append("&" + OAuth2Utils.SCOPE + "=").append(encode(OAuth2Utils.formatParameterList(accessToken.getScope())));
        }

        Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
        for (String key : additionalInformation.keySet()) {
            Object value = additionalInformation.get(key);
            if (value != null) {
                url.append("&" + encode(key) + "=" + encode(value.toString()));
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
            String code = authorizationCodeServices.createAuthorizationCode(combinedAuth);

            return code;

        } catch (OAuth2Exception e) {

            if (authorizationRequest.getState() != null) {
                e.addAdditionalInformation("state", authorizationRequest.getState());
            }

            throw e;

        }
    }

    private String encode(String value) {
        try {
            //return URLEncoder.encode(value,"UTF-8");
            return UriUtils.encodeQueryParam(value, "UTF-8");
        } catch (UnsupportedEncodingException x) {
            throw new IllegalArgumentException(x);
        }
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

        values.append("error=" + encode(failure.getOAuth2ErrorCode()));
        values.append("&error_description=" + encode(failure.getMessage()));

        if (authorizationRequest.getState() != null) {
            values.append("&state=" + encode(authorizationRequest.getState()));
        }

        if (failure.getAdditionalInformation() != null) {
            for (Map.Entry<String, String> additionalInfo : failure.getAdditionalInformation().entrySet()) {
                values.append("&" + encode(additionalInfo.getKey()) + "=" + encode(additionalInfo.getValue()));
            }
        }

        if (fragment) {
            template.fragment(values.toString());
        } else {
            template.query(values.toString());
        }

        return template.build(true).toUriString();

    }

    public void setUserApprovalPage(String userApprovalPage) {
        this.userApprovalPage = userApprovalPage;
    }

    public void setAuthorizationCodeServices(AuthorizationCodeServices authorizationCodeServices) {
        this.authorizationCodeServices = authorizationCodeServices;
    }

    public void setRedirectResolver(RedirectResolver redirectResolver) {
        this.redirectResolver = redirectResolver;
    }

    public void setUserApprovalHandler(UserApprovalHandler userApprovalHandler) {
        this.userApprovalHandler = userApprovalHandler;
    }

    public void setOAuth2RequestValidator(OAuth2RequestValidator oauth2RequestValidator) {
        this.oauth2RequestValidator = oauth2RequestValidator;
    }

    @SuppressWarnings("deprecation")
    public void setImplicitGrantService(org.springframework.security.oauth2.provider.implicit.ImplicitGrantService implicitGrantService) {
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
        webRequest.getResponse().setStatus(translate.getStatusCode().value());

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
                getClientServiceExtention().loadClientByClientId(authorizationRequest.getClientId(), IdentityZoneHolder.get().getId()));
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

        Map<String, String> parameters = new HashMap<String, String>();
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

    protected ClientServicesExtension getClientServiceExtention() {
        return (ClientServicesExtension) super.getClientDetailsService();
    }


    public void setClientDetailsService(ClientServicesExtension clientDetailsService) {
        super.setClientDetailsService(clientDetailsService);
    }

    public HybridTokenGranterForAuthorizationCode getHybridTokenGranterForAuthCode() {
        return hybridTokenGranterForAuthCode;
    }

    public void setHybridTokenGranterForAuthCode(HybridTokenGranterForAuthorizationCode hybridTokenGranterForAuthCode) {
        this.hybridTokenGranterForAuthCode = hybridTokenGranterForAuthCode;
    }

    public void setSessionAttributeStore(SessionAttributeStore sessionAttributeStore) {
        this.sessionAttributeStore = sessionAttributeStore;
    }

    public void setErrorPage(String errorPage) {
        this.errorPage = errorPage;
    }


    public OpenIdSessionStateCalculator getOpenIdSessionStateCalculator() {
        return openIdSessionStateCalculator;
    }

    public void setOpenIdSessionStateCalculator(OpenIdSessionStateCalculator openIdSessionStateCalculator) {
        this.openIdSessionStateCalculator = openIdSessionStateCalculator;
    }
}
