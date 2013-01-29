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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.openid.UserInfo;
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

public class UaaTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices, InitializingBean {

	private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; // default 30 days.
	private int accessTokenValiditySeconds = 60 * 60 * 12; // default 12 hours.

	private final Log logger = LogFactory.getLog(getClass());
	private UaaUserDatabase userDatabase = null;
	private ObjectMapper mapper = new ObjectMapper();
	private ClientDetailsService clientDetailsService = null;
	private SignerProvider signerProvider = new SignerProvider();
	private String issuer = null;
	private Set<String> defaultUserAuthorities = new HashSet<String>();

	public enum ClaimsConstants {
		USER_NAME,
		EXP,
		CLIENT_ID,
		EMAIL,
		AUTHORITIES,
		SCOPE,
		JTI,
		AUD,
		SUB,
		ISS,
		IAT,
		CID;

		public String value() {
			return this.name().toLowerCase();
		}
	}

	@Override
	public OAuth2AccessToken refreshAccessToken(String refreshTokenValue,
			AuthorizationRequest request) throws AuthenticationException {

		if (null == refreshTokenValue) {
			throw new InvalidTokenException("Invalid refresh token (empty token)");
		}

		if (!"refresh_token".equals(request.getAuthorizationParameters().get("grant_type"))) {
			throw new InvalidGrantException("Invalid grant type: " + request.getAuthorizationParameters().get("grant_type"));
		}

		Map<String, Object> claims = getClaimsForToken(refreshTokenValue);

		//TODO: Should reuse the access token you get after the first successful authentication.
		//You will get an invalid_grant error if your previous token has not expired yet.
//		OAuth2RefreshToken refreshToken = tokenStore.readRefreshToken(refreshTokenValue);
//		if (refreshToken == null) {
//			throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
//		}

		String username = (String)claims.get(ClaimsConstants.USER_NAME.value());
		//TODO: Need to add a lookup by id so that the refresh token does not need to contain a name
		UaaUser user = userDatabase.retrieveUserByName(username);

		Integer refreshTokenIssuedAt = (Integer)claims.get(ClaimsConstants.IAT.value());
		long refreshTokenIssueDate = refreshTokenIssuedAt.longValue() * 1000l;

		//If the user changed their password, expire the refresh token
		if(user.getModified().after(new Date(refreshTokenIssueDate))) {
			logger.debug("User was last modified at " + user.getModified() + " refresh token was issued at " + new Date(refreshTokenIssuedAt));
			throw new InvalidTokenException("Invalid refresh token (password changed): " + refreshTokenValue);
		}

		Integer refreshTokenExpiry = (Integer)claims.get(ClaimsConstants.EXP.value());
		long refreshTokenExpireDate = refreshTokenExpiry.longValue() * 1000l;

		if (new Date(refreshTokenExpireDate).before(new Date())) {
			throw new InvalidTokenException("Invalid refresh token (expired): " + refreshTokenValue + " expired at " + new Date(refreshTokenExpireDate));
		}

		String clientId = (String) claims.get(ClaimsConstants.CID.value());
		if (clientId == null || !clientId.equals(request.getClientId())) {
			throw new InvalidGrantException("Wrong client for this refresh token: " + refreshTokenValue);
		}


		@SuppressWarnings("unchecked")
		ArrayList<String> originalScopes = (ArrayList<String>) claims.get(ClaimsConstants.SCOPE.value());
		//The user may not request scopes that were not part of the refresh token
		Set<String>requestedScopes = request.getScope();
		if (originalScopes.isEmpty() || !originalScopes.containsAll(requestedScopes)) {
			throw new InvalidScopeException("Unable to narrow the scope of the client authentication to " + requestedScopes
					+ ".", new HashSet<String>(originalScopes));
		}

		int validitySeconds = getAccessTokenValiditySeconds(clientId);

		OAuth2AccessToken accessToken = createAccessToken(user.getId(),
														  user.getUsername(),
														  user.getEmail(),
														  validitySeconds,
														  null,
														  requestedScopes,
														  clientId,
														  request.getResourceIds(),
														  refreshTokenValue);

		return accessToken;
	}

	private OAuth2AccessToken createAccessToken(String userId,
												String username,
												String userEmail,
												int validitySeconds,
												Collection<GrantedAuthority> clientScopes,
												Set<String> requestedScopes,
												String clientId,
												Set<String> resourceIds,
												String refreshToken) throws AuthenticationException {
		String tokenId = UUID.randomUUID().toString();
		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(tokenId);
		if (validitySeconds > 0) {
			accessToken.setExpiration(new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));
		}
		accessToken.setRefreshToken(refreshToken == null ? null : new DefaultOAuth2RefreshToken(refreshToken));
		accessToken.setScope(requestedScopes);

		Map<String, Object> info = new HashMap<String, Object>();
		info.put(ClaimsConstants.JTI.value(), accessToken.getValue());
		accessToken.setAdditionalInformation(info);

		String content;
		try {
			content = mapper.writeValueAsString(createJWTAccessToken(accessToken,
																	 userId,
																	 username,
																	 userEmail,
																	 clientScopes,
																	 requestedScopes,
																	 clientId,
																	 resourceIds,
																	 refreshToken));
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot convert access token to JSON", e);
		}
		String token = JwtHelper.encode(content, signerProvider.getSigner()).getEncoded();

		//This setter copies the value and returns. Don't change.
		accessToken = accessToken.setValue(token);

		return accessToken;
	}


	private Map<String, ?> createJWTAccessToken(OAuth2AccessToken token,
												String userId,
												String username,
												String userEmail,
												Collection<GrantedAuthority> clientScopes,
												Set<String> requestedScopes,
												String clientId,
												Set<String> resourceIds,
												String refreshToken) {

		Map<String, Object> response = new LinkedHashMap<String, Object>();

		response.put(ClaimsConstants.JTI.value(), token.getAdditionalInformation().get(ClaimsConstants.JTI.value()));
		response.putAll(token.getAdditionalInformation());

		response.put(UserInfo.USER_ID, userId);
		response.put(ClaimsConstants.SUB.value(), userId);
		response.put(UserInfo.USER_NAME, username == null ? userId : username);
		if (null != userEmail) {
			response.put(UserInfo.EMAIL, userEmail);
		}

		if (null != clientScopes) {
			response.put(ClaimsConstants.AUTHORITIES.value(), AuthorityUtils.authorityListToSet(clientScopes));
		}

		response.put(OAuth2AccessToken.SCOPE, requestedScopes);
		response.put(ClaimsConstants.CLIENT_ID.value(), clientId);
		response.put(ClaimsConstants.CID.value(), clientId);

		response.put(ClaimsConstants.IAT.value(), System.currentTimeMillis() / 1000);
		if (token.getExpiration() != null) {
			response.put(ClaimsConstants.EXP.value(), token.getExpiration().getTime() / 1000);
		}

		if (issuer != null) {
			String tokenEndpoint = issuer + "/oauth/token";
			response.put(ClaimsConstants.ISS.value(), tokenEndpoint);
		}

		//TODO: different values for audience in the AT and RT. Need to sync them up
		response.put(ClaimsConstants.AUD.value(), resourceIds);


		return response;
	}

	protected int getAccessTokenValiditySeconds(String clientId) {
		ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
		Integer validity = client.getAccessTokenValiditySeconds();
		if (validity != null) {
			return validity;
		}
		return accessTokenValiditySeconds;
	}

	@Override
	public OAuth2AccessToken createAccessToken(
			OAuth2Authentication authentication) throws AuthenticationException {

		OAuth2RefreshToken refreshToken = createRefreshToken(authentication);

		String userId = null;
		String username = null;
		String userEmail = null;

		Collection<GrantedAuthority> clientScopes = null;
		//Clients should really by different kinds of users
		if (authentication.isClientOnly()) {
			ClientDetails client = clientDetailsService.loadClientByClientId(authentication.getName());
			userId = client.getClientId();
			clientScopes = client.getAuthorities();
		} else {
			UaaUser user = userDatabase.retrieveUserByName(authentication.getName());
			userId = user.getId();
			username = user.getUsername();
			userEmail = user.getEmail();
		}

		String clientId = authentication.getAuthorizationRequest().getClientId();
		Set<String> userScopes = authentication.getAuthorizationRequest().getScope();

		OAuth2AccessToken accessToken = createAccessToken(userId,
														  username,
														  userEmail,
														  getAccessTokenValiditySeconds(clientId),
														  clientScopes,
														  userScopes,
														  clientId,
														  authentication.getAuthorizationRequest().getResourceIds(),
														  refreshToken != null ? refreshToken.getValue() : null);

		return accessToken;

	}

	private ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {
		if (!isRefreshTokenSupported(authentication.getAuthorizationRequest())) {
			return null;
		}
		int validitySeconds = getRefreshTokenValiditySeconds(authentication.getAuthorizationRequest());
		ExpiringOAuth2RefreshToken token = new DefaultExpiringOAuth2RefreshToken(UUID.randomUUID().toString(),
				new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));

		UaaUser user = userDatabase.retrieveUserByName(((Principal) authentication.getPrincipal()).getName());

		String content;
		try {
			content = mapper.writeValueAsString(createJWTRefreshToken(token,
																	user,
																	authentication.getAuthorizationRequest().getScope(),
																	authentication.getAuthorizationRequest().getClientId()));
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot convert access token to JSON", e);
		}
		String jwtToken = JwtHelper.encode(content, signerProvider.getSigner()).getEncoded();

		ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken(jwtToken, token.getExpiration());

		return refreshToken;
	}

	private Map<String, ?> createJWTRefreshToken(OAuth2RefreshToken token,
												UaaUser user,
												Set<String> scopes,
												String clientId) {

		Map<String, Object> response = new LinkedHashMap<String, Object>();

		response.put(ClaimsConstants.JTI.value(), UUID.randomUUID().toString());
		response.put(ClaimsConstants.SUB.value(), user.getId());
		response.put(ClaimsConstants.USER_NAME.value(), user.getUsername());
		response.put(ClaimsConstants.SCOPE.value(), scopes);

		response.put(ClaimsConstants.IAT.value(), System.currentTimeMillis() / 1000);
		if (((ExpiringOAuth2RefreshToken)token).getExpiration() != null) {
			response.put(ClaimsConstants.EXP.value(), ((ExpiringOAuth2RefreshToken)token).getExpiration().getTime() / 1000);
		}

		response.put(ClaimsConstants.CID.value(), clientId);
		if (issuer != null) {
			String tokenEndpoint = issuer + "/oauth/token";
			response.put(ClaimsConstants.ISS.value(), tokenEndpoint);
		}

		response.put(ClaimsConstants.AUD.value(), scopes);

		return response;
	}


	/**
	 * Is a refresh token supported for this client (or the global setting if
	 * {@link #setClientDetailsService(ClientDetailsService) clientDetailsService} is not set.
	 * @param authorizationRequest the current authorization request
	 * @return boolean to indicate if refresh token is supported
	 */
	protected boolean isRefreshTokenSupported(AuthorizationRequest authorizationRequest) {
		String grantType = authorizationRequest.getAuthorizationParameters().get("grant_type");

		return "authorization_code".equals(grantType) ||
			   "password".equals(grantType) ||
			   "refresh_token".equals(grantType);
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
	}

	public void setUserDatabase(UaaUserDatabase userDatabase) {
		this.userDatabase = userDatabase;
	}

	@Override
	public OAuth2Authentication loadAuthentication(String accessToken)
			throws AuthenticationException {
		Map<String, Object> claims = getClaimsForToken(accessToken);

		@SuppressWarnings("unchecked")
		ArrayList<String> scopes = (ArrayList<String>) claims.get(ClaimsConstants.SCOPE.value());

		AuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest((String) claims.get(ClaimsConstants.CLIENT_ID.value()), scopes);
		((DefaultAuthorizationRequest) authorizationRequest).setResourceIds(null);
		((DefaultAuthorizationRequest) authorizationRequest).setApproved(true);

		Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils
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
		//Is this a user token?
		if (claims.containsKey(ClaimsConstants.EMAIL.value())) {
			UaaUser user = new UaaUser((String)claims.get(UserInfo.USER_ID),
									   (String) claims.get(ClaimsConstants.USER_NAME.value()),
									   null,
									   (String) claims.get(ClaimsConstants.EMAIL.value()),
									   UaaAuthority.USER_AUTHORITIES,
									   null,
									   null,
									   null,
									   null);

			UaaPrincipal principal = new UaaPrincipal(user);
			userAuthentication = new UaaAuthentication(principal, UaaAuthority.USER_AUTHORITIES, null);
		} else {
			((DefaultAuthorizationRequest) authorizationRequest).setAuthorities(authorities);
		}

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		authentication.setAuthenticated(true);
		return authentication;
	}


	/**
	 * This method is implemented only to support older API calls that assume the
	 * presence of a token store
	 */
	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		Map<String, Object> claims = getClaimsForToken(accessToken);

		//Expiry is verified by check_token
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(accessToken);
		token.setTokenType(OAuth2AccessToken.BEARER_TYPE);
		Integer exp = (Integer) claims.get(ClaimsConstants.EXP.value());
		if (null != exp) {
			token.setExpiration(new Date(exp.longValue() * 1000l));
		}

		@SuppressWarnings("unchecked")
		ArrayList<String> scopes = (ArrayList<String>) claims.get(ClaimsConstants.SCOPE.value());
		if (null != scopes && scopes.size() > 0) {
			token.setScope(new HashSet<String>(scopes));
		}

		return token;
	}

	private Map<String, Object> getClaimsForToken(String token) {
		Jwt tokenJwt = null;
		try {
			tokenJwt = JwtHelper.decodeAndVerify(token, signerProvider.getVerifier());
		} catch (Throwable t) {
			logger.debug("Invalid token (could not decode)");
			throw new InvalidTokenException("Invalid token (could not decode): " + token);
		}

		Map<String, Object> claims = null;
		try {
			claims = mapper.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		return claims;
	}

	/**
	 * This method is implemented only to support older API calls that assume the
	 * presence of a token store
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

}
