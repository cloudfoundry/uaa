package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.oauth.beans.LegacyRedirectResolver;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.approval.DefaultUserApprovalHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.approval.UserApprovalHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.code.InMemoryAuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.request.DefaultOAuth2RequestValidator;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
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
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.security.Principal;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;


@FrameworkEndpoint
@SessionAttributes({AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTR_NAME, AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME})
public class AuthorizationEndpoint extends AbstractEndpoint {
	static final String AUTHORIZATION_REQUEST_ATTR_NAME = "authorizationRequest";

	static final String ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME = "org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST";

	private AuthorizationCodeServices authorizationCodeServices = new InMemoryAuthorizationCodeServices();

	private RedirectResolver redirectResolver = new LegacyRedirectResolver();

	private UserApprovalHandler userApprovalHandler = new DefaultUserApprovalHandler();

	private SessionAttributeStore sessionAttributeStore = new DefaultSessionAttributeStore();

	private OAuth2RequestValidator oauth2RequestValidator = new DefaultOAuth2RequestValidator();

	private String userApprovalPage = "forward:/oauth/confirm_access";

	private String errorPage = "forward:/oauth/error";

	private Object implicitLock = new Object();

	public void setSessionAttributeStore(SessionAttributeStore sessionAttributeStore) {
		this.sessionAttributeStore = sessionAttributeStore;
	}

	public void setErrorPage(String errorPage) {
		this.errorPage = errorPage;
	}

	@RequestMapping(value = "/oauth/authorize")
	public ModelAndView authorize(Map<String, Object> model, @RequestParam Map<String, String> parameters,
			SessionStatus sessionStatus, Principal principal) {

		// Pull out the authorization request first, using the OAuth2RequestFactory. All further logic should
		// query off of the authorization request instead of referring back to the parameters map. The contents of the
		// parameters map will be stored without change in the AuthorizationRequest object once it is created.
		AuthorizationRequest authorizationRequest = getOAuth2RequestFactory().createAuthorizationRequest(parameters);

		Set<String> responseTypes = authorizationRequest.getResponseTypes();

		if (!responseTypes.contains("token") && !responseTypes.contains("code")) {
			throw new UnsupportedResponseTypeException("Unsupported response types");
		}

		if (authorizationRequest.getClientId() == null) {
			throw new InvalidClientException("A client id must be provided");
		}

		try {

			if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
				throw new InsufficientAuthenticationException(
						"User must be authenticated with Spring Security before authorization can be completed.");
			}

			ClientDetails client = getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId());

			// The resolved redirect URI is either the redirect_uri from the parameters or the one from
			// clientDetails. Either way we need to store it on the AuthorizationRequest.
			String redirectUriParameter = authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI);
			String resolvedRedirect = redirectResolver.resolveRedirect(redirectUriParameter, client);
			if (!StringUtils.hasText(resolvedRedirect)) {
				throw new RedirectMismatchException(
						"A redirectUri must be either supplied or preconfigured in the ClientDetails");
			}
			authorizationRequest.setRedirectUri(resolvedRedirect);

			// We intentionally only validate the parameters requested by the client (ignoring any data that may have
			// been added to the request by the manager).
			oauth2RequestValidator.validateScope(authorizationRequest, client);

			// Some systems may allow for approval decisions to be remembered or approved by default. Check for
			// such logic here, and set the approved flag on the authorization request accordingly.
			authorizationRequest = userApprovalHandler.checkForPreApproval(authorizationRequest,
					(Authentication) principal);
			// TODO: is this call necessary?
			boolean approved = userApprovalHandler.isApproved(authorizationRequest, (Authentication) principal);
			authorizationRequest.setApproved(approved);

			// Validation is all done, so we can check for auto approval...
			if (authorizationRequest.isApproved()) {
				if (responseTypes.contains("token")) {
					return getImplicitGrantResponse(authorizationRequest);
				}
				if (responseTypes.contains("code")) {
					return new ModelAndView(getAuthorizationCodeResponse(authorizationRequest,
							(Authentication) principal));
				}
			}

			// Store authorizationRequest AND an immutable Map of authorizationRequest in session
			// which will be used to validate against in approveOrDeny()
			model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
			model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, unmodifiableMap(authorizationRequest));

			return getUserApprovalPageResponse(model, authorizationRequest, (Authentication) principal);

		}
		catch (RuntimeException e) {
			sessionStatus.setComplete();
			throw e;
		}

	}

	Map<String, Object> unmodifiableMap(AuthorizationRequest authorizationRequest) {
		Map<String, Object> authorizationRequestMap = new HashMap<String, Object>();

		authorizationRequestMap.put(OAuth2Utils.CLIENT_ID, authorizationRequest.getClientId());
		authorizationRequestMap.put(OAuth2Utils.STATE, authorizationRequest.getState());
		authorizationRequestMap.put(OAuth2Utils.REDIRECT_URI, authorizationRequest.getRedirectUri());
		if (authorizationRequest.getResponseTypes() != null) {
			authorizationRequestMap.put(OAuth2Utils.RESPONSE_TYPE,
					Collections.unmodifiableSet(new HashSet<String>(authorizationRequest.getResponseTypes())));
		}
		if (authorizationRequest.getScope() != null) {
			authorizationRequestMap.put(OAuth2Utils.SCOPE,
					Collections.unmodifiableSet(new HashSet<String>(authorizationRequest.getScope())));
		}
		authorizationRequestMap.put("approved", authorizationRequest.isApproved());
		if (authorizationRequest.getResourceIds() != null) {
			authorizationRequestMap.put("resourceIds",
					Collections.unmodifiableSet(new HashSet<String>(authorizationRequest.getResourceIds())));
		}
		if (authorizationRequest.getAuthorities() != null) {
			authorizationRequestMap.put("authorities",
					Collections.unmodifiableSet(new HashSet<GrantedAuthority>(authorizationRequest.getAuthorities())));
		}

		return Collections.unmodifiableMap(authorizationRequestMap);
	}

	@RequestMapping(value = "/oauth/authorize", method = RequestMethod.POST, params = OAuth2Utils.USER_OAUTH_APPROVAL)
	public View approveOrDeny(@RequestParam Map<String, String> approvalParameters, Map<String, ?> model,
			SessionStatus sessionStatus, Principal principal) {

		if (!(principal instanceof Authentication)) {
			sessionStatus.setComplete();
			throw new InsufficientAuthenticationException(
					"User must be authenticated with Spring Security before authorizing an access token.");
		}

		AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get(AUTHORIZATION_REQUEST_ATTR_NAME);

		if (authorizationRequest == null) {
			sessionStatus.setComplete();
			throw new InvalidRequestException("Cannot approve uninitialized authorization request.");
		}

		// Check to ensure the Authorization Request was not modified during the user approval step
		@SuppressWarnings("unchecked")
		Map<String, Object> originalAuthorizationRequest = (Map<String, Object>) model.get(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME);
		if (isAuthorizationRequestModified(authorizationRequest, originalAuthorizationRequest)) {
			throw new InvalidRequestException("Changes were detected from the original authorization request.");
		}

		try {
			Set<String> responseTypes = authorizationRequest.getResponseTypes();

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
				RedirectView redirectView = new RedirectView(getUnsuccessfulRedirect(authorizationRequest,
						new UserDeniedAuthorizationException("User denied access"), responseTypes.contains("token")),
						false, true, false);
				redirectView.setStatusCode(HttpStatus.SEE_OTHER);
				return redirectView;
			}

			if (responseTypes.contains("token")) {
				return getImplicitGrantResponse(authorizationRequest).getView();
			}

			return getAuthorizationCodeResponse(authorizationRequest, (Authentication) principal);
		}
		finally {
			sessionStatus.setComplete();
		}

	}

	private boolean isAuthorizationRequestModified(
			AuthorizationRequest authorizationRequest, Map<String, Object> originalAuthorizationRequest) {
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
				authorizationRequest.getScope(),
				originalAuthorizationRequest.get(OAuth2Utils.SCOPE))) {
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

		return false;
	}

	// We need explicit approval from the user.
	private ModelAndView getUserApprovalPageResponse(Map<String, Object> model,
			AuthorizationRequest authorizationRequest, Authentication principal) {
		if (logger.isDebugEnabled()) {
			logger.debug("Loading user approval page: " + userApprovalPage);
		}
		model.putAll(userApprovalHandler.getUserApprovalRequest(authorizationRequest, principal));
		return new ModelAndView(userApprovalPage, model);
	}

	// We can grant a token and return it with implicit approval.
	private ModelAndView getImplicitGrantResponse(AuthorizationRequest authorizationRequest) {
		try {
			TokenRequest tokenRequest = getOAuth2RequestFactory().createTokenRequest(authorizationRequest, "implicit");
			OAuth2Request storedOAuth2Request = getOAuth2RequestFactory().createOAuth2Request(authorizationRequest);
			OAuth2AccessToken accessToken = getAccessTokenForImplicitGrant(tokenRequest, storedOAuth2Request);
			if (accessToken == null) {
				throw new UnsupportedResponseTypeException("Unsupported response type: token");
			}
			setCacheControlHeaders();
			RedirectView redirectView = new RedirectView(appendAccessToken(authorizationRequest, accessToken), false, true,
				false);
			redirectView.setStatusCode(HttpStatus.SEE_OTHER);
			return new ModelAndView(redirectView);
		}
		catch (OAuth2Exception e) {
				RedirectView redirectView = new RedirectView(getUnsuccessfulRedirect(authorizationRequest, e, true), false,
					true, false);
				redirectView.setStatusCode(HttpStatus.SEE_OTHER);
				return new ModelAndView(redirectView);
		}
	}

	private OAuth2AccessToken getAccessTokenForImplicitGrant(TokenRequest tokenRequest,
			OAuth2Request storedOAuth2Request) {
		OAuth2AccessToken accessToken = null;
		// These 1 method calls have to be atomic, otherwise the ImplicitGrantService can have a race condition where
		// one thread removes the token request before another has a chance to redeem it.
		synchronized (this.implicitLock) {
			accessToken = getTokenGranter().grant("implicit",
					new ImplicitTokenRequest(tokenRequest, storedOAuth2Request));
		}
		return accessToken;
	}

	private View getAuthorizationCodeResponse(AuthorizationRequest authorizationRequest, Authentication authUser) {
		try {
				RedirectView redirectView = new RedirectView(getSuccessfulRedirect(authorizationRequest,
					generateCode(authorizationRequest, authUser)), false, true, false);
				redirectView.setStatusCode(HttpStatus.SEE_OTHER);
				return redirectView;
		}
		catch (OAuth2Exception e) {
				RedirectView redirectView = new RedirectView(getUnsuccessfulRedirect(authorizationRequest, e, false), false, true, false);
				redirectView.setStatusCode(HttpStatus.SEE_OTHER);
				return redirectView;
		}
	}

	private String appendAccessToken(AuthorizationRequest authorizationRequest, OAuth2AccessToken accessToken) {

		Map<String, Object> vars = new LinkedHashMap<String, Object>();
		Map<String, String> keys = new HashMap<String, String>();

		if (accessToken == null) {
			throw new InvalidRequestException("An implicit grant could not be made");
		}

		vars.put("access_token", accessToken.getValue());
		vars.put("token_type", accessToken.getTokenType());
		String state = authorizationRequest.getState();

		if (state != null) {
			vars.put("state", state);
		}
		Date expiration = accessToken.getExpiration();
		if (expiration != null) {
			long expires_in = (expiration.getTime() - System.currentTimeMillis()) / 1000;
			vars.put("expires_in", expires_in);
		}
		String originalScope = authorizationRequest.getRequestParameters().get(OAuth2Utils.SCOPE);
		if (originalScope == null || !OAuth2Utils.parseParameterList(originalScope).equals(accessToken.getScope())) {
			vars.put(OAuth2Utils.SCOPE, OAuth2Utils.formatParameterList(accessToken.getScope()));
		}
		Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
		for (String key : additionalInformation.keySet()) {
			Object value = additionalInformation.get(key);
			if (value != null) {
				keys.put("extra_" + key, key);
				vars.put("extra_" + key, value);
			}
		}
		// Do not include the refresh token (even if there is one)
		return append(authorizationRequest.getRedirectUri(), vars, keys, true);
	}

	private String generateCode(AuthorizationRequest authorizationRequest, Authentication authentication)
			throws AuthenticationException {

		try {

			OAuth2Request storedOAuth2Request = getOAuth2RequestFactory().createOAuth2Request(authorizationRequest);

			OAuth2Authentication combinedAuth = new OAuth2Authentication(storedOAuth2Request, authentication);
			String code = authorizationCodeServices.createAuthorizationCode(combinedAuth);

			return code;

		}
		catch (OAuth2Exception e) {

			if (authorizationRequest.getState() != null) {
				e.addAdditionalInformation("state", authorizationRequest.getState());
			}

			throw e;

		}
	}

	private String getSuccessfulRedirect(AuthorizationRequest authorizationRequest, String authorizationCode) {

		if (authorizationCode == null) {
			throw new IllegalStateException("No authorization code found in the current request scope.");
		}

		Map<String, String> query = new LinkedHashMap<String, String>();
		query.put("code", authorizationCode);

		String state = authorizationRequest.getState();
		if (state != null) {
			query.put("state", state);
		}

		return append(authorizationRequest.getRedirectUri(), query, false);
	}

	private String getUnsuccessfulRedirect(AuthorizationRequest authorizationRequest, OAuth2Exception failure,
			boolean fragment) {

		if (authorizationRequest == null || authorizationRequest.getRedirectUri() == null) {
			// we have no redirect for the user. very sad.
			throw new UnapprovedClientAuthenticationException("Authorization failure, and no redirect URI.", failure);
		}

		Map<String, String> query = new LinkedHashMap<String, String>();

		query.put("error", failure.getOAuth2ErrorCode());
		query.put("error_description", failure.getMessage());

		if (authorizationRequest.getState() != null) {
			query.put("state", authorizationRequest.getState());
		}

		if (failure.getAdditionalInformation() != null) {
			for (Map.Entry<String, String> additionalInfo : failure.getAdditionalInformation().entrySet()) {
				query.put(additionalInfo.getKey(), additionalInfo.getValue());
			}
		}

		return append(authorizationRequest.getRedirectUri(), query, fragment);

	}

	private String append(String base, Map<String, ?> query, boolean fragment) {
		return append(base, query, null, fragment);
	}

	private String append(String base, Map<String, ?> query, Map<String, String> keys, boolean fragment) {

		UriComponentsBuilder template = UriComponentsBuilder.newInstance();
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(base);
		URI redirectUri;
		try {
			// assume it's encoded to start with (if it came in over the wire)
			redirectUri = builder.build(true).toUri();
		}
		catch (Exception e) {
			// ... but allow client registrations to contain hard-coded non-encoded values
			redirectUri = builder.build().toUri();
			builder = UriComponentsBuilder.fromUri(redirectUri);
		}
		template.scheme(redirectUri.getScheme()).port(redirectUri.getPort()).host(redirectUri.getHost())
				.userInfo(redirectUri.getUserInfo()).path(redirectUri.getPath());

		if (fragment) {
			StringBuilder values = new StringBuilder();
			if (redirectUri.getFragment() != null) {
				String append = redirectUri.getFragment();
				values.append(append);
			}
			for (String key : query.keySet()) {
				if (values.length() > 0) {
					values.append("&");
				}
				String name = key;
				if (keys != null && keys.containsKey(key)) {
					name = keys.get(key);
				}
				values.append(name + "={" + key + "}");
			}
			if (values.length() > 0) {
				template.fragment(values.toString());
			}
			UriComponents encoded = template.build().expand(query).encode();
			builder.fragment(encoded.getFragment());
		}
		else {
			for (String key : query.keySet()) {
				String name = key;
				if (keys != null && keys.containsKey(key)) {
					name = keys.get(key);
				}
				template.queryParam(name, "{" + key + "}");
			}
			template.fragment(redirectUri.getFragment());
			UriComponents encoded = template.build().expand(query).encode();
			builder.query(encoded.getQuery());
		}

		return builder.build().toUriString();

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
	public void setImplicitGrantService(
			org.springframework.security.oauth2.provider.implicit.ImplicitGrantService implicitGrantService) {
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
			return new ModelAndView(errorPage, Collections.singletonMap("error", translate.getBody()));
		}

		AuthorizationRequest authorizationRequest = null;
		try {
			authorizationRequest = getAuthorizationRequestForError(webRequest);
			String requestedRedirectParam = authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI);
			String requestedRedirect = redirectResolver.resolveRedirect(requestedRedirectParam,
					getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId()));
			authorizationRequest.setRedirectUri(requestedRedirect);
			String redirect = getUnsuccessfulRedirect(authorizationRequest, translate.getBody(), authorizationRequest
					.getResponseTypes().contains("token"));
			RedirectView redirectView = new RedirectView(redirect, false, true, false);
			redirectView.setStatusCode(HttpStatus.SEE_OTHER);
			return new ModelAndView(redirectView);
		}
		catch (OAuth2Exception ex) {
			// If an AuthorizationRequest cannot be created from the incoming parameters it must be
			// an error. OAuth2Exception can be handled this way. Other exceptions will generate a standard 500
			// response.
			return new ModelAndView(errorPage, Collections.singletonMap("error", translate.getBody()));
		}

	}

	private AuthorizationRequest getAuthorizationRequestForError(ServletWebRequest webRequest) {

		// If it's already there then we are in the approveOrDeny phase and we can use the saved request
		AuthorizationRequest authorizationRequest = (AuthorizationRequest) sessionAttributeStore.retrieveAttribute(
				webRequest, AUTHORIZATION_REQUEST_ATTR_NAME);
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
		}
		catch (Exception e) {
			return getDefaultOAuth2RequestFactory().createAuthorizationRequest(parameters);
		}

	}
	
	private void setCacheControlHeaders() {
		ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		if (servletRequestAttributes != null) {
			HttpServletResponse servletResponse = servletRequestAttributes.getResponse();
			servletResponse.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
			servletResponse.setHeader(HttpHeaders.PRAGMA, "no-cache");
		}
	}
}
