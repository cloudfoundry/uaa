package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.client.grant.AuthorizationCodeAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.grant.ClientCredentialsAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.grant.ImplicitAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.grant.ResourceOwnerPasswordAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.http.AccessTokenRequiredException;
import org.cloudfoundry.identity.uaa.oauth.client.http.OAuth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.AuthenticationScheme;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenProviderChain;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Calendar;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class OAuth2RestTemplate extends RestTemplate implements OAuth2RestOperations {

	private final OAuth2ProtectedResourceDetails resource;

	private AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(
			Arrays.<AccessTokenProvider> asList(
					new AuthorizationCodeAccessTokenProvider(), new ImplicitAccessTokenProvider(),
					new ResourceOwnerPasswordAccessTokenProvider(), new ClientCredentialsAccessTokenProvider()));

	private OAuth2ClientContext context;

	private boolean retryBadAccessTokens = true;

	private OAuth2RequestAuthenticator authenticator = new DefaultOAuth2RequestAuthenticator();

	private int clockSkew = 30;

	public OAuth2RestTemplate(OAuth2ProtectedResourceDetails resource) {
		this(resource, new DefaultOAuth2ClientContext());
	}

	public OAuth2RestTemplate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
		super();
		if (resource == null) {
			throw new IllegalArgumentException("An OAuth2 resource must be supplied.");
		}

		this.resource = resource;
		this.context = context;
		setErrorHandler(new OAuth2ErrorHandler(resource));
	}

	/**
	 * Strategy for extracting an Authorization header from an access token and the request details. Defaults to the
	 * simple form "TOKEN_TYPE TOKEN_VALUE".
	 *
	 * @param authenticator the authenticator to use
	 */
	public void setAuthenticator(OAuth2RequestAuthenticator authenticator) {
		this.authenticator = authenticator;
	}

	/**
	 * Flag to determine whether a request that has an existing access token, and which then leads to an
	 * AccessTokenRequiredException should be retried (immediately, once). Useful if the remote server doesn't recognize
	 * an old token which is stored in the client, but is happy to re-grant it.
	 *
	 * @param retryBadAccessTokens the flag to set (default true)
	 */
	public void setRetryBadAccessTokens(boolean retryBadAccessTokens) {
		this.retryBadAccessTokens = retryBadAccessTokens;
	}

	@Override
	public void setErrorHandler(ResponseErrorHandler errorHandler) {
		if (!(errorHandler instanceof OAuth2ErrorHandler)) {
			errorHandler = new OAuth2ErrorHandler(errorHandler, resource);
		}
		super.setErrorHandler(errorHandler);
	}

	@Override
	public OAuth2ProtectedResourceDetails getResource() {
		return resource;
	}

	@Override
	protected ClientHttpRequest createRequest(URI uri, HttpMethod method) throws IOException {

		OAuth2AccessToken accessToken = getAccessToken();

		AuthenticationScheme authenticationScheme = resource.getAuthenticationScheme();
		if (AuthenticationScheme.query.equals(authenticationScheme)
				|| AuthenticationScheme.form.equals(authenticationScheme)) {
			uri = appendQueryParameter(uri, accessToken);
		}

		ClientHttpRequest req = super.createRequest(uri, method);

		if (AuthenticationScheme.header.equals(authenticationScheme)) {
			authenticator.authenticate(resource, getOAuth2ClientContext(), req);
		}
		return req;

	}

	@Override
	protected <T> T doExecute(URI url, HttpMethod method, RequestCallback requestCallback,
			ResponseExtractor<T> responseExtractor) throws RestClientException {
		OAuth2AccessToken accessToken = context.getAccessToken();
		RuntimeException rethrow = null;
		try {
			return super.doExecute(url, method, requestCallback, responseExtractor);
		}
		catch (AccessTokenRequiredException | OAuth2AccessDeniedException e) {
			rethrow = e;
		}
		catch (InvalidTokenException e) {
			// Don't reveal the token value in case it is logged
			rethrow = new OAuth2AccessDeniedException("Invalid token for client=" + getClientId());
		}
		if (accessToken != null && retryBadAccessTokens) {
			context.setAccessToken(null);
			try {
				return super.doExecute(url, method, requestCallback, responseExtractor);
			}
			catch (InvalidTokenException e) {
				// Don't reveal the token value in case it is logged
				rethrow = new OAuth2AccessDeniedException("Invalid token for client=" + getClientId());
			}
		}
		throw rethrow;
	}

	/**
	 * @return the client id for this resource.
	 */
	private String getClientId() {
		return resource.getClientId();
	}

	/**
	 * Acquire or renew an access token for the current context if necessary. This method will be called automatically
	 * when a request is executed (and the result is cached), but can also be called as a standalone method to
	 * pre-populate the token.
	 *
	 * @return an access token
	 */
	public OAuth2AccessToken getAccessToken() throws UserRedirectRequiredException {

		OAuth2AccessToken accessToken = context.getAccessToken();

		if (accessToken == null || hasTokenExpired(accessToken)) {
			try {
				accessToken = acquireAccessToken(context);
			}
			catch (UserRedirectRequiredException e) {
				context.setAccessToken(null); // No point hanging onto it now
        String stateKey = e.getStateKey();
				if (stateKey != null) {
					Object stateToPreserve = e.getStateToPreserve();
					if (stateToPreserve == null) {
						stateToPreserve = "NONE";
					}
					context.setPreservedState(stateKey, stateToPreserve);
				}
				throw e;
			}
		}
		return accessToken;
	}

	private boolean hasTokenExpired(OAuth2AccessToken accessToken) {
		Calendar now = Calendar.getInstance();
		Calendar expiresAt = (Calendar) now.clone();
		if (accessToken.getExpiration() != null) {
			expiresAt.setTime(accessToken.getExpiration());
			expiresAt.add(Calendar.SECOND, -this.clockSkew);
		}
		return now.after(expiresAt);
	}

	/**
	 * @return the context for this template
	 */
	public OAuth2ClientContext getOAuth2ClientContext() {
		return context;
	}

	protected OAuth2AccessToken acquireAccessToken(OAuth2ClientContext oauth2Context)
			throws UserRedirectRequiredException {

		AccessTokenRequest accessTokenRequest = oauth2Context.getAccessTokenRequest();
		if (accessTokenRequest == null) {
			throw new AccessTokenRequiredException(
					"No OAuth 2 security context has been established. Unable to access resource '"
							+ this.resource.getId() + "'.", resource);
		}

		// Transfer the preserved state from the (longer lived) context to the current request.
		String stateKey = accessTokenRequest.getStateKey();
		if (stateKey != null) {
			accessTokenRequest.setPreservedState(oauth2Context.removePreservedState(stateKey));
		}

		OAuth2AccessToken existingToken = oauth2Context.getAccessToken();
		if (existingToken != null) {
			accessTokenRequest.setExistingToken(existingToken);
		}

		OAuth2AccessToken accessToken = null;
		accessToken = accessTokenProvider.obtainAccessToken(resource, accessTokenRequest);
		if (accessToken == null || accessToken.getValue() == null) {
			throw new IllegalStateException(
					"Access token provider returned a null access token, which is illegal according to the contract.");
		}
		oauth2Context.setAccessToken(accessToken);
		return accessToken;
	}

	protected URI appendQueryParameter(URI uri, OAuth2AccessToken accessToken) {

		try {
			String query = uri.getRawQuery(); // Don't decode anything here
			String queryFragment = resource.getTokenName() + "=" + URLEncoder.encode(accessToken.getValue(), "UTF-8");
			if (query == null) {
				query = queryFragment;
			}
			else {
				query = query + "&" + queryFragment;
			}

			// first form the URI without query and fragment parts, so that it doesn't re-encode some query string chars
			// (SECOAUTH-90)
			URI update = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), uri.getPath(), null,
					null);
			// now add the encoded query string and the then fragment
			StringBuilder sb = new StringBuilder(update.toString());
			sb.append("?");
			sb.append(query);
			if (uri.getFragment() != null) {
				sb.append("#");
				sb.append(uri.getFragment());
			}

			return new URI(sb.toString());

		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException("Could not parse URI", e);
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalArgumentException("Could not encode URI", e);
		}

	}

	public void setAccessTokenProvider(AccessTokenProvider accessTokenProvider) {
		this.accessTokenProvider = accessTokenProvider;
		propagateClockSkewToAccessTokenProvider(this.clockSkew, accessTokenProvider);
	}

	/**
	 * Sets the maximum acceptable clock skew, which is used when checking the
	 * {@link OAuth2AccessToken access token} expiry. The default is 30 seconds.
	 *
	 * @param clockSkew the maximum acceptable clock skew
	 */
	public void setClockSkew(int clockSkew) {
		Assert.isTrue(clockSkew >= 0, "clockSkew must be >= 0");
		this.clockSkew = clockSkew;
		propagateClockSkewToAccessTokenProvider(clockSkew, this.accessTokenProvider);
	}

	/**
	 * Propagates the maximum acceptable clock skew, which is used when checking the
	 * {@link OAuth2AccessToken access token} expiry into the given {@link AccessTokenProvider} if it is an instance of
	 * {@link AccessTokenProviderChain}.
	 * <p>
	 * <b>Note:</b> The clock skew value is injected via reflection as version 2.5.0 was the final minor release before EOL of
	 * this project and the public API must not be changed in patch releases.
	 *
	 * @param clockSkew the maximum acceptable clock skew
	 * @param accessTokenProvider the access token provider
	 */
	private static void propagateClockSkewToAccessTokenProvider(int clockSkew, AccessTokenProvider accessTokenProvider) {
		if (!(accessTokenProvider instanceof AccessTokenProviderChain)) {
			return;
		}

		Field field = ReflectionUtils.findField(accessTokenProvider.getClass(), "clockSkew");
		if (field == null) {
			return;
		}
		field.setAccessible(true);
		ReflectionUtils.setField(field, accessTokenProvider, clockSkew);
	}
}