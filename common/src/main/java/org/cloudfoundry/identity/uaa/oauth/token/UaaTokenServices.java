/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth.token;

import static org.cloudfoundry.identity.uaa.oauth.Claims.AUD;
import static org.cloudfoundry.identity.uaa.oauth.Claims.AUTHORITIES;
import static org.cloudfoundry.identity.uaa.oauth.Claims.CID;
import static org.cloudfoundry.identity.uaa.oauth.Claims.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.Claims.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.Claims.EXP;
import static org.cloudfoundry.identity.uaa.oauth.Claims.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.Claims.IAT;
import static org.cloudfoundry.identity.uaa.oauth.Claims.ISS;
import static org.cloudfoundry.identity.uaa.oauth.Claims.JTI;
import static org.cloudfoundry.identity.uaa.oauth.Claims.SCOPE;
import static org.cloudfoundry.identity.uaa.oauth.Claims.SUB;
import static org.cloudfoundry.identity.uaa.oauth.Claims.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.Claims.USER_NAME;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.oauth.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * This class provides token services for the UAA. It handles the production and consumption of UAA tokens.
 *
 * @author Joel D'sa
 *
 */
public class UaaTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices,
		InitializingBean {

	private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; // default 30 days.

	private int accessTokenValiditySeconds = 60 * 60 * 12; // default 12 hours.

	private final Log logger = LogFactory.getLog(getClass());

	private UaaUserDatabase userDatabase = null;

	private ObjectMapper mapper = new ObjectMapper();

	private ClientDetailsService clientDetailsService = null;

	private SignerProvider signerProvider = new SignerProvider();

	private String issuer = null;

	private Set<String> defaultUserAuthorities = new HashSet<String>();

	private ApprovalStore approvalStore = null;

	@Override
	public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, AuthorizationRequest request)
			throws AuthenticationException {

		if (null == refreshTokenValue) {
			throw new InvalidTokenException("Invalid refresh token (empty token)");
		}

		if (!"refresh_token".equals(request.getAuthorizationParameters().get("grant_type"))) {
			throw new InvalidGrantException("Invalid grant type: "
					+ request.getAuthorizationParameters().get("grant_type"));
		}

		Map<String, Object> claims = getClaimsForToken(refreshTokenValue);

		// TODO: Should reuse the access token you get after the first successful authentication.
		// You will get an invalid_grant error if your previous token has not expired yet.
		// OAuth2RefreshToken refreshToken = tokenStore.readRefreshToken(refreshTokenValue);
		// if (refreshToken == null) {
		// throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
		// }

		String clientId = (String) claims.get(CID);
		if (clientId == null || !clientId.equals(request.getClientId())) {
			throw new InvalidGrantException("Wrong client for this refresh token: " + refreshTokenValue);
		}

		String username = (String) claims.get(USER_NAME);

		// TODO: Need to add a lookup by id so that the refresh token does not need to contain a name
		UaaUser user = userDatabase.retrieveUserByName(username);

		Integer refreshTokenIssuedAt = (Integer) claims.get(IAT);
		long refreshTokenIssueDate = refreshTokenIssuedAt.longValue() * 1000l;

		// If the user changed their password, expire the refresh token
		if (user.getModified().after(new Date(refreshTokenIssueDate))) {
			logger.debug("User was last modified at " + user.getModified() + " refresh token was issued at "
					+ new Date(refreshTokenIssueDate));
			throw new InvalidTokenException("Invalid refresh token (password changed): " + refreshTokenValue);
		}

		Integer refreshTokenExpiry = (Integer) claims.get(EXP);
		long refreshTokenExpireDate = refreshTokenExpiry.longValue() * 1000l;

		if (new Date(refreshTokenExpireDate).before(new Date())) {
			throw new InvalidTokenException("Invalid refresh token (expired): " + refreshTokenValue + " expired at "
					+ new Date(refreshTokenExpireDate));
		}

		@SuppressWarnings("unchecked")
		ArrayList<String> tokenScopes = (ArrayList<String>) claims.get(SCOPE);

		// default request scopes to what is in the refresh token
		Set<String> requestedScopes = request.getScope();
		if (requestedScopes.isEmpty()) {
			requestedScopes = new HashSet<String>(tokenScopes);
		}

		// The user may not request scopes that were not part of the refresh token
		if (tokenScopes.isEmpty() || !tokenScopes.containsAll(requestedScopes)) {
			throw new InvalidScopeException("Unable to narrow the scope of the client authentication to "
					+ requestedScopes + ".", new HashSet<String>(tokenScopes));
		}

		// from this point on, we only care about the scopes requested, not what is in the refresh token
		// ensure all requested scopes are approved: either automatically or explicitly by the user
		ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
		String grantType = claims.get(GRANT_TYPE).toString();
		checkForApproval(username, clientId, requestedScopes,
								getAutoApprovedScopes(grantType, tokenScopes, client),
								new Date(refreshTokenIssueDate));

		// if we have reached so far, issue an access token
		Integer validity = client.getAccessTokenValiditySeconds();

		OAuth2AccessToken accessToken = createAccessToken(user.getId(), user.getUsername(), user.getEmail(),
				validity != null ? validity.intValue() : accessTokenValiditySeconds, null, requestedScopes, clientId,
				request.getResourceIds(), grantType, refreshTokenValue);

		return accessToken;
	}

	private void checkForApproval (String username, String clientId, Collection<String> requestedScopes, Collection<String> autoApprovedScopes, Date updateCutOff) {
		Set<String> approvedScopes = new HashSet<String>();
		approvedScopes.addAll(autoApprovedScopes);

		// Search through the users approvals for scopes that are requested, not auto approved, not expired,
		// not DENIED and not approved more recently than when this access token was issued.
		List<Approval> approvals = approvalStore.getApprovals(username, clientId);
		for (Approval approval : approvals) {
			if (requestedScopes.contains(approval.getScope()) && approval.getStatus() == ApprovalStatus.APPROVED) {
				if (!approval.isCurrentlyActive()) {
					logger.debug("Approval " + approval + " has expired. Need to re-approve.");
					throw new InvalidTokenException("Invalid token (approvals expired)");
				}
				if (updateCutOff.before(approval.getLastUpdatedAt())) {
					logger.debug("At least one approval " + approval + " was updated more recently at "
										 + approval.getLastUpdatedAt() + " access token was issued at "
										 + updateCutOff);
					throw new InvalidTokenException("Invalid token (approvals updated): " + approval.getLastUpdatedAt());
				}
				approvedScopes.add(approval.getScope());
			}
		}

		// Only issue the token if all the requested scopes have unexpired approvals made before the refresh token was
		// issued OR if those scopes are auto approved
		if (!approvedScopes.containsAll(requestedScopes)) {
			logger.debug("All requested scopes " + requestedScopes + " were not approved " + approvedScopes);
			Set<String> unapprovedScopes = new HashSet<String>(requestedScopes);
			unapprovedScopes.removeAll(approvedScopes);
			throw new InvalidTokenException("Invalid token (some requested scopes are not approved): " + unapprovedScopes);
		}
	}

	private OAuth2AccessToken createAccessToken(String userId, String username, String userEmail, int validitySeconds,
			Collection<GrantedAuthority> clientScopes, Set<String> requestedScopes, String clientId,
			Set<String> resourceIds, String grantType, String refreshToken) throws AuthenticationException {
		String tokenId = UUID.randomUUID().toString();
		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(tokenId);
		if (validitySeconds > 0) {
			accessToken.setExpiration(new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));
		}
		accessToken.setRefreshToken(refreshToken == null ? null : new DefaultOAuth2RefreshToken(refreshToken));

		if (null == requestedScopes || requestedScopes.size() == 0) {
			logger.debug("No scopes were granted");
			throw new InvalidTokenException("No scopes were granted");
		}

		accessToken.setScope(requestedScopes);

		Map<String, Object> info = new HashMap<String, Object>();
		info.put(JTI, accessToken.getValue());
		accessToken.setAdditionalInformation(info);

		String content;
		try {
			content = mapper.writeValueAsString(createJWTAccessToken(accessToken, userId, username, userEmail,
					clientScopes, requestedScopes, clientId, resourceIds, grantType, refreshToken));
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot convert access token to JSON", e);
		}
		String token = JwtHelper.encode(content, signerProvider.getSigner()).getEncoded();

		// This setter copies the value and returns. Don't change.
		accessToken = accessToken.setValue(token);

		return accessToken;
	}

	private Map<String, ?> createJWTAccessToken(OAuth2AccessToken token, String userId, String username,
			String userEmail, Collection<GrantedAuthority> clientScopes, Set<String> requestedScopes, String clientId,
			Set<String> resourceIds, String grantType, String refreshToken) {

		Map<String, Object> response = new LinkedHashMap<String, Object>();

		response.put(JTI, token.getAdditionalInformation().get(JTI));
		response.putAll(token.getAdditionalInformation());

		response.put(SUB, userId);
		if (null != clientScopes) {
			response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(clientScopes));
		}

		response.put(OAuth2AccessToken.SCOPE, requestedScopes);
		response.put(CLIENT_ID, clientId);
		response.put(CID, clientId);

		if (null != grantType) {
			response.put(GRANT_TYPE, grantType);
		}
		if(!"client_credentials".equals(grantType)) {
			response.put(USER_ID, userId);
			response.put(USER_NAME, username == null ? userId : username);
			if (null != userEmail) {
				response.put(EMAIL, userEmail);
			}
		}

		response.put(IAT, System.currentTimeMillis() / 1000);
		if (token.getExpiration() != null) {
			response.put(EXP, token.getExpiration().getTime() / 1000);
		}

		if (issuer != null) {
			String tokenEndpoint = issuer + "/oauth/token";
			response.put(ISS, tokenEndpoint);
		}

		// TODO: different values for audience in the AT and RT. Need to sync them up
		response.put(AUD, resourceIds);

		return response;
	}

	@Override
	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {

		OAuth2RefreshToken refreshToken = createRefreshToken(authentication);

		String userId = null;
		String username = null;
		String userEmail = null;

		Collection<GrantedAuthority> clientScopes = null;
		// Clients should really by different kinds of users
		if (authentication.isClientOnly()) {
			ClientDetails client = clientDetailsService.loadClientByClientId(authentication.getName());
			userId = client.getClientId();
			clientScopes = client.getAuthorities();
		}
		else {
			UaaUser user = userDatabase.retrieveUserByName(authentication.getName());
			userId = user.getId();
			username = user.getUsername();
			userEmail = user.getEmail();
		}

		String clientId = authentication.getAuthorizationRequest().getClientId();
		Set<String> userScopes = authentication.getAuthorizationRequest().getScope();
		String grantType = authentication.getAuthorizationRequest().getAuthorizationParameters().get("grant_type");

		ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
		Integer validity = client.getAccessTokenValiditySeconds();

		OAuth2AccessToken accessToken = createAccessToken(userId, username, userEmail,
				validity != null ? validity.intValue() : accessTokenValiditySeconds, clientScopes, userScopes,
				clientId, authentication.getAuthorizationRequest().getResourceIds(), grantType,
				refreshToken != null ? refreshToken.getValue() : null);

		return accessToken;

	}

	private ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {

		String grantType = authentication.getAuthorizationRequest().getAuthorizationParameters().get("grant_type");
		if (!isRefreshTokenSupported(grantType)) {
			return null;
		}

		int validitySeconds = getRefreshTokenValiditySeconds(authentication.getAuthorizationRequest());
		ExpiringOAuth2RefreshToken token = new DefaultExpiringOAuth2RefreshToken(UUID.randomUUID().toString(),
				new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));

		UaaUser user = userDatabase.retrieveUserByName(((Principal) authentication.getPrincipal()).getName());

		String content;
		try {
			content = mapper.writeValueAsString(createJWTRefreshToken(token, user, authentication
					.getAuthorizationRequest().getScope(), authentication.getAuthorizationRequest().getClientId(), grantType));
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot convert access token to JSON", e);
		}
		String jwtToken = JwtHelper.encode(content, signerProvider.getSigner()).getEncoded();

		ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken(jwtToken, token.getExpiration());

		return refreshToken;
	}

	private Map<String, ?> createJWTRefreshToken(OAuth2RefreshToken token, UaaUser user, Set<String> scopes,
			String clientId, String grantType) {

		Map<String, Object> response = new LinkedHashMap<String, Object>();

		response.put(JTI, UUID.randomUUID().toString());
		response.put(SUB, user.getId());
		response.put(SCOPE, scopes);

		response.put(IAT, System.currentTimeMillis() / 1000);
		if (((ExpiringOAuth2RefreshToken) token).getExpiration() != null) {
			response.put(EXP, ((ExpiringOAuth2RefreshToken) token).getExpiration().getTime() / 1000);
		}

		response.put(CID, clientId);
		if (issuer != null) {
			String tokenEndpoint = issuer + "/oauth/token";
			response.put(ISS, tokenEndpoint);
		}

		if (null != grantType) {
			response.put(GRANT_TYPE, grantType);
		}
		if (!"client_credentials".equals(grantType)) {
			response.put(USER_NAME, user.getUsername());
		}

		response.put(AUD, scopes);

		return response;
	}

	/**
	 * Check the current authorization request to indicate whether a refresh token should be issued or not.
	 * @param grantType the current grant type
	 * @return boolean to indicate if refresh token is supported
	 */
	protected boolean isRefreshTokenSupported(String grantType) {
		return "authorization_code".equals(grantType) || "password".equals(grantType)
				|| "refresh_token".equals(grantType);
	}

	/**
	 * The refresh token validity period in seconds
	 * @param authorizationRequest the current authorization request
	 * @return the refresh token validity period in seconds
	 */
	protected int getRefreshTokenValiditySeconds(AuthorizationRequest authorizationRequest) {
		ClientDetails client = clientDetailsService.loadClientByClientId(authorizationRequest.getClientId());
		Integer validity = client.getRefreshTokenValiditySeconds();
		if (validity != null) {
			return validity;
		}
		return refreshTokenValiditySeconds;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(clientDetailsService, "clientDetailsService must be set");
		Assert.notNull(issuer, "issuer must be set");
		Assert.notNull(approvalStore, "approvalStore must be set");
	}

	public void setUserDatabase(UaaUserDatabase userDatabase) {
		this.userDatabase = userDatabase;
	}

	@Override
	public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {
		Map<String, Object> claims = getClaimsForToken(accessToken);

		@SuppressWarnings("unchecked")
		ArrayList<String> scopes = (ArrayList<String>) claims.get(SCOPE);

		AuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest((String) claims.get(CLIENT_ID),
				scopes);
		((DefaultAuthorizationRequest) authorizationRequest).setResourceIds(null);
		((DefaultAuthorizationRequest) authorizationRequest).setApproved(true);

		Collection<? extends GrantedAuthority> authorities = AuthorityUtils
				.commaSeparatedStringToAuthorityList(StringUtils
						.collectionToCommaDelimitedString(defaultUserAuthorities));
		if (claims.containsKey("authorities")) {
			Object authoritiesFromClaims = claims.get("authorities");
			if (authoritiesFromClaims instanceof String) {
				authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) authoritiesFromClaims);
			}
			if (authoritiesFromClaims instanceof Collection) {
				authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils
						.collectionToCommaDelimitedString((Collection<?>) authoritiesFromClaims));
			}
		}

		Authentication userAuthentication = null;
		// Is this a user token?
		if (claims.containsKey(EMAIL)) {
			UaaUser user = new UaaUser((String) claims.get(USER_ID), (String) claims.get(USER_NAME), null,
					(String) claims.get(EMAIL), UaaAuthority.USER_AUTHORITIES, null, null, null, null);

			UaaPrincipal principal = new UaaPrincipal(user);
			userAuthentication = new UaaAuthentication(principal, UaaAuthority.USER_AUTHORITIES, null);
		}
		else {
			((DefaultAuthorizationRequest) authorizationRequest).setAuthorities(authorities);
		}

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		authentication.setAuthenticated(true);
		return authentication;
	}

	/**
	 * This method is implemented to support older API calls that assume the presence of a token store
	 */
	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		Map<String, Object> claims = getClaimsForToken(accessToken);

		// Expiry is verified by check_token
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(accessToken);
		token.setTokenType(OAuth2AccessToken.BEARER_TYPE);
		Integer exp = (Integer) claims.get(EXP);
		if (null != exp) {
			token.setExpiration(new Date(exp.longValue() * 1000l));
		}

		@SuppressWarnings("unchecked")
		ArrayList<String> scopes = (ArrayList<String>) claims.get(SCOPE);
		if (null != scopes && scopes.size() > 0) {
			token.setScope(new HashSet<String>(scopes));
		}

		String email = (String) claims.get(EMAIL);

		// Only check user access tokens
		if (null != email) {
			String username = (String) claims.get(USER_NAME);

			UaaUser user = userDatabase.retrieveUserByName(username);

			Integer accessTokenIssuedAt = (Integer) claims.get(IAT);
			long accessTokenIssueDate = accessTokenIssuedAt.longValue() * 1000l;

			// If the user changed their password, expire the access token
			if (user.getModified().after(new Date(accessTokenIssueDate))) {
				logger.debug("User was last modified at " + user.getModified() + " access token was issued at "
						+ new Date(accessTokenIssueDate));
				throw new InvalidTokenException("Invalid access token (password changed): " + accessToken);
			}

			// Check approvals to make sure they're all valid, approved and not more recent
			// than the token itself
			String clientId = (String) claims.get(CLIENT_ID);
			ClientDetails client = clientDetailsService.loadClientByClientId(clientId);

			@SuppressWarnings("unchecked")
			ArrayList<String> tokenScopes = (ArrayList<String>) claims.get(SCOPE);
			Set<String> autoApprovedScopes = getAutoApprovedScopes(claims.get(GRANT_TYPE), tokenScopes, client);
			if (autoApprovedScopes.containsAll(tokenScopes)) {
				return token;
			}
			checkForApproval(username, clientId, tokenScopes, autoApprovedScopes, new Date(accessTokenIssueDate));
		}

		return token;
	}

	private Set<String> getAutoApprovedScopes(Object grantType, Collection<String> tokenScopes, ClientDetails client) {
		// ALL requested scopes are considered auto-approved for password grant
		if (grantType != null && "password".equals(grantType.toString())) {
			return new HashSet<String>(tokenScopes);
		}

		// start with scopes listed as autoapprove in client config
		Object autoApproved = client.getAdditionalInformation().get("autoapprove");
		Set<String> autoApprovedScopes = new HashSet<String>();
		if (autoApproved instanceof Collection<?>) {
			@SuppressWarnings("unchecked")
			Collection<? extends String> approvedScopes = (Collection<? extends String>) autoApproved;
			autoApprovedScopes.addAll(approvedScopes);
		} else if (autoApproved instanceof Boolean && (Boolean) autoApproved || "true".equals(autoApproved)) {
			autoApprovedScopes.addAll(client.getScope());
		}

		// retain only the requested scopes
		autoApprovedScopes.retainAll(tokenScopes);
		return autoApprovedScopes;
	}

	private Map<String, Object> getClaimsForToken(String token) {
		Jwt tokenJwt = null;
		try {
			tokenJwt = JwtHelper.decodeAndVerify(token, signerProvider.getVerifier());
		}
		catch (Throwable t) {
			logger.debug("Invalid token (could not decode)");
			throw new InvalidTokenException("Invalid token (could not decode): " + token);
		}

		Map<String, Object> claims = null;
		try {
			claims = mapper.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
			});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		return claims;
	}

	/**
	 * This method is implemented only to support older API calls that assume the presence of a token store
	 */
	@Override
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		return null;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public void setSignerProvider(SignerProvider signerProvider) {
		this.signerProvider = signerProvider;
	}

	public void setDefaultUserAuthorities(Set<String> defaultUserAuthorities) {
		this.defaultUserAuthorities = defaultUserAuthorities;
	}

	public void setApprovalStore(ApprovalStore approvalStore) {
		this.approvalStore = approvalStore;
	}

}
