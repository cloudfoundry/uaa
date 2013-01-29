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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;


public class UaaTokenServicesTests {

	private UaaTokenServices tokenServices = new UaaTokenServices();
	private SignerProvider signerProvider = new SignerProvider();
	private ObjectMapper mapper = new ObjectMapper();

	//Need to create a user with a modified time slightly in the past because the token IAT is in seconds and the token expiry
	//skew will not be long enough
	private InMemoryUaaUserDatabase userDatabase = new InMemoryUaaUserDatabase(new HashMap<String, UaaUser>(Collections.singletonMap("jdsa",
			new UaaUser("12345", "jdsa", "password", "jdsa@vmware.com", UaaAuthority.USER_AUTHORITIES, null, null,
					new Date(System.currentTimeMillis() - 15000), new Date(System.currentTimeMillis() - 15000)))));
	private InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

	public UaaTokenServicesTests() {
		clientDetailsService.setClientDetailsStore(Collections.singletonMap("client",
				new BaseClientDetails("client", "scim. clients", "read, write", "authorization_code, password, implicit, client_credentials", "update")));
		tokenServices.setClientDetailsService(clientDetailsService);
		tokenServices.setDefaultUserAuthorities(AuthorityUtils.authorityListToSet(UaaAuthority.USER_AUTHORITIES));
		tokenServices.setIssuer("http://localhost:8080/uaa");
		tokenServices.setSignerProvider(signerProvider);
		tokenServices.setUserDatabase(userDatabase);
	}

	@Test
	public void testCreateAccessTokenForAClient() {

		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "client_credentials");
		authorizationRequest.setAuthorizationParameters(azParameters);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, null);

		OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
		Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
		assertNotNull(tokenJwt);
		Map<String, Object> claims = null;
		try {
			claims = mapper.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		assertEquals(claims.get("iss"), "http://localhost:8080/uaa/oauth/token");
		assertEquals(claims.get("client_id"), "client");
		assertEquals(claims.get("user_id"), "client");
		assertEquals(claims.get("sub"), "client");
		assertEquals(claims.get("user_name"), "client");
		assertEquals(claims.get("cid"), "client");
		assertEquals(claims.get("scope"), Arrays.asList(new String[]{"read", "write"}));
		assertEquals(claims.get("aud"), Arrays.asList(new String[]{"scim", "clients"}));
		assertTrue(((String)claims.get("jti")).length() > 0);
		assertTrue(((Integer)claims.get("iat")) > 0);
		assertTrue(((Integer)claims.get("exp")) > 0);
		assertTrue(((Integer)claims.get("exp")) - ((Integer)claims.get("iat")) == 60 * 60 * 12);
		assertNull(accessToken.getRefreshToken());
	}

	@Test
	public void testCreateAccessTokenAuthcodeGrant() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "authorization_code");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		testCreateAccessTokenForAUser(authentication, false);
	}

	@Test
	public void testCreateAccessTokenPasswordGrant() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "password");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		testCreateAccessTokenForAUser(authentication, false);
	}

	@Test
	public void testCreateAccessTokenRefreshGrant() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "authorization_code");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

		DefaultAuthorizationRequest refreshAuthorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		refreshAuthorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> refreshAzParameters = new HashMap<String, String>(refreshAuthorizationRequest.getAuthorizationParameters());
		refreshAzParameters.put("grant_type", "refresh_token");
		refreshAuthorizationRequest.setAuthorizationParameters(refreshAzParameters);

		OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), refreshAuthorizationRequest);

		assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());
	}

	@Test
	public void testCreateAccessTokenImplicitGrant() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "implicit");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		testCreateAccessTokenForAUser(authentication, true);
	}


	private OAuth2AccessToken testCreateAccessTokenForAUser(OAuth2Authentication authentication, boolean noRefreshToken) {
		OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
		Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
		assertNotNull(tokenJwt);
		Map<String, Object> claims = null;
		try {
			claims = mapper.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		assertEquals(claims.get("iss"), "http://localhost:8080/uaa/oauth/token");
		assertEquals(claims.get("client_id"), "client");
		assertNotNull(claims.get("user_id"));
		assertNotNull(claims.get("sub"));
		assertEquals(claims.get("user_name"), "jdsa");
		assertEquals(claims.get("email"), "jdsa@vmware.com");
		assertEquals(claims.get("cid"), "client");
		assertEquals(claims.get("scope"), Arrays.asList(new String[]{"read", "write"}));
		assertEquals(claims.get("aud"), Arrays.asList(new String[]{"scim", "clients"}));
		assertTrue(((String)claims.get("jti")).length() > 0);
		assertTrue(((Integer)claims.get("iat")) > 0);
		assertTrue(((Integer)claims.get("exp")) > 0);
		assertTrue(((Integer)claims.get("exp")) - ((Integer)claims.get("iat")) == 60 * 60 * 12);
		if (noRefreshToken) {
			assertNull(accessToken.getRefreshToken());
		} else {
			assertNotNull(accessToken.getRefreshToken());

			Jwt refreshTokenJwt = JwtHelper.decodeAndVerify(accessToken.getRefreshToken().getValue(), signerProvider.getVerifier());
			assertNotNull(refreshTokenJwt);
			Map<String, Object> refreshTokenClaims = null;
			try {
				refreshTokenClaims = mapper.readValue(refreshTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
			}
			catch (Exception e) {
				throw new IllegalStateException("Cannot read token claims", e);
			}

			assertEquals(refreshTokenClaims.get("iss"), "http://localhost:8080/uaa/oauth/token");
			assertNotNull(refreshTokenClaims.get("user_name"));
			assertNotNull(refreshTokenClaims.get("sub"));
			assertEquals(refreshTokenClaims.get("cid"), "client");
			assertEquals(refreshTokenClaims.get("scope"), Arrays.asList(new String[]{"read", "write"}));
			assertEquals(refreshTokenClaims.get("aud"), Arrays.asList(new String[]{"read", "write"}));
			assertTrue(((String)refreshTokenClaims.get("jti")).length() > 0);
			assertTrue(((Integer)refreshTokenClaims.get("iat")) > 0);
			assertTrue(((Integer)refreshTokenClaims.get("exp")) > 0);
			assertTrue(((Integer)refreshTokenClaims.get("exp")) - ((Integer)refreshTokenClaims.get("iat")) == 60 * 60 * 24 * 30);
		}

		return accessToken;
	}

	@Test
	public void testCreateAccessTokenAuthcodeGrantNarrowerScopes() {
		//First Request
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "authorization_code");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
		Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
		assertNotNull(tokenJwt);
		Map<String, Object> claims = null;
		try {
			claims = mapper.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		assertEquals(claims.get("scope"), Arrays.asList(new String[]{"read", "write"}));
		assertNotNull(accessToken.getRefreshToken());

		Jwt refreshTokenJwt = JwtHelper.decodeAndVerify(accessToken.getRefreshToken().getValue(), signerProvider.getVerifier());
		assertNotNull(refreshTokenJwt);
		Map<String, Object> refreshTokenClaims = null;
		try {
			refreshTokenClaims = mapper.readValue(refreshTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		assertEquals(refreshTokenClaims.get("scope"), Arrays.asList(new String[]{"read", "write"}));
		assertEquals(refreshTokenClaims.get("aud"), Arrays.asList(new String[]{"read", "write"}));

		//Second request with reduced scopes
		DefaultAuthorizationRequest reducedScopeAuthorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read"}));
		reducedScopeAuthorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> refreshAzParameters = new HashMap<String, String>(reducedScopeAuthorizationRequest.getAuthorizationParameters());
		refreshAzParameters.put("grant_type", "refresh_token");
		reducedScopeAuthorizationRequest.setAuthorizationParameters(refreshAzParameters);

		OAuth2Authentication reducedScopeAuthentication = new OAuth2Authentication(reducedScopeAuthorizationRequest, userAuthentication);
		OAuth2AccessToken reducedScopeAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(),
																					reducedScopeAuthentication.getAuthorizationRequest());

		//AT should have the new scopes, RT should be the same
		Jwt newTokenJwt = JwtHelper.decodeAndVerify(reducedScopeAccessToken.getValue(), signerProvider.getVerifier());
		assertNotNull(tokenJwt);
		Map<String, Object> reducedClaims = null;
		try {
			reducedClaims = mapper.readValue(newTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		assertEquals(reducedClaims.get("scope"), Arrays.asList(new String[]{"read"}));
		assertEquals(reducedScopeAccessToken.getRefreshToken(), accessToken.getRefreshToken());
	}

	@Test(expected = InvalidScopeException.class)
	public void testCreateAccessTokenAuthcodeGrantExpandedScopes() {
		//First Request
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "authorization_code");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
		Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
		assertNotNull(tokenJwt);
		Map<String, Object> claims = null;
		try {
			claims = mapper.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		assertEquals(claims.get("scope"), Arrays.asList(new String[]{"read", "write"}));
		assertNotNull(accessToken.getRefreshToken());

		Jwt refreshTokenJwt = JwtHelper.decodeAndVerify(accessToken.getRefreshToken().getValue(), signerProvider.getVerifier());
		assertNotNull(refreshTokenJwt);
		Map<String, Object> refreshTokenClaims = null;
		try {
			refreshTokenClaims = mapper.readValue(refreshTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		assertEquals(refreshTokenClaims.get("scope"), Arrays.asList(new String[]{"read", "write"}));
		assertEquals(refreshTokenClaims.get("aud"), Arrays.asList(new String[]{"read", "write"}));

		//Second request with expanded scopes
		DefaultAuthorizationRequest expandedScopeAuthorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write", "delete"}));
		expandedScopeAuthorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> refreshAzParameters = new HashMap<String, String>(expandedScopeAuthorizationRequest.getAuthorizationParameters());
		refreshAzParameters.put("grant_type", "refresh_token");
		expandedScopeAuthorizationRequest.setAuthorizationParameters(refreshAzParameters);

		OAuth2Authentication expandedScopeAuthentication = new OAuth2Authentication(expandedScopeAuthorizationRequest, userAuthentication);
		tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(),
										expandedScopeAuthentication.getAuthorizationRequest());
	}

	@Test
	public void testChangedExpiryForTokens() {
		BaseClientDetails clientDetails = new BaseClientDetails("client", "scim. clients", "read, write", "authorization_code, password, implicit, client_credentials", "update");
		clientDetails.setAccessTokenValiditySeconds(3600);
		clientDetails.setRefreshTokenValiditySeconds(36000);
		clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", clientDetails));

		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "authorization_code");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
		Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
		assertNotNull(tokenJwt);
		Map<String, Object> claims = null;
		try {
			claims = mapper.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		assertTrue(((Integer)claims.get("iat")) > 0);
		assertTrue(((Integer)claims.get("exp")) > 0);
		assertTrue(((Integer)claims.get("exp")) - ((Integer)claims.get("iat")) == 3600);
		assertNotNull(accessToken.getRefreshToken());

		Jwt refreshTokenJwt = JwtHelper.decodeAndVerify(accessToken.getRefreshToken().getValue(), signerProvider.getVerifier());
		assertNotNull(refreshTokenJwt);
		Map<String, Object> refreshTokenClaims = null;
		try {
			refreshTokenClaims = mapper.readValue(refreshTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		assertTrue(((Integer)refreshTokenClaims.get("iat")) > 0);
		assertTrue(((Integer)refreshTokenClaims.get("exp")) > 0);
		assertTrue(((Integer)refreshTokenClaims.get("exp")) - ((Integer)refreshTokenClaims.get("iat")) == 36000);
	}

	@Test(expected = InvalidTokenException.class)
	public void testUserUpdatedAfterRefreshTokenIssued() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "authorization_code");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

		UaaUser user = userDatabase.retrieveUserByName("jdsa");
		UaaUser newUser = new UaaUser(user.getUsername(), "blah", user.getEmail(), null, null);
		userDatabase.updateUser("jdsa", newUser);

		DefaultAuthorizationRequest refreshAuthorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		refreshAuthorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> refreshAzParameters = new HashMap<String, String>(refreshAuthorizationRequest.getAuthorizationParameters());
		refreshAzParameters.put("grant_type", "refresh_token");
		refreshAuthorizationRequest.setAuthorizationParameters(refreshAzParameters);

		tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), refreshAuthorizationRequest);
	}

	@Test(expected = InvalidTokenException.class)
	public void testRefreshTokenExpiry() {
		BaseClientDetails clientDetails = new BaseClientDetails("client", "scim. clients", "read, write", "authorization_code, password, implicit, client_credentials", "update");
		//Back date the refresh token. Crude way to do this but i'm not sure of another
		clientDetails.setRefreshTokenValiditySeconds(-36000);
		clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", clientDetails));

		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "authorization_code");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

		DefaultAuthorizationRequest refreshAuthorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		refreshAuthorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> refreshAzParameters = new HashMap<String, String>(refreshAuthorizationRequest.getAuthorizationParameters());
		refreshAzParameters.put("grant_type", "refresh_token");
		refreshAuthorizationRequest.setAuthorizationParameters(refreshAzParameters);

		tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), refreshAuthorizationRequest);
	}

	@Test
	public void testReadAccessToken() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "authorization_code");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);
		assertEquals(accessToken, tokenServices.readAccessToken(accessToken.getValue()));
	}

	@Test
	public void testLoadAuthenticationForAUser() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "authorization_code");
		authorizationRequest.setAuthorizationParameters(azParameters);
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(new UaaUser("jdsa", "password", "jdsa@vmware.com", null, null)), "n/a", null);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, userAuthentication);
		OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);
		OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

		assertEquals(UaaAuthority.USER_AUTHORITIES, loadedAuthentication.getAuthorities());
		assertEquals("jdsa", loadedAuthentication.getName());
		UaaPrincipal uaaPrincipal = new UaaPrincipal(new UaaUser("12345", "jdsa", "password", "jdsa@vmware.com", UaaAuthority.USER_AUTHORITIES, null, null, null, null));
		assertEquals(uaaPrincipal, loadedAuthentication.getPrincipal());
		assertNull(loadedAuthentication.getDetails());

		Authentication userAuth = loadedAuthentication.getUserAuthentication();
		assertEquals("jdsa", userAuth.getName());
		assertEquals(uaaPrincipal, userAuth.getPrincipal());
		assertTrue(userAuth.isAuthenticated());
	}

	@Test
	public void testLoadAuthenticationForAClient() {
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList(new String[]{"read", "write"}));
		authorizationRequest.setResourceIds(new HashSet<String>(Arrays.asList(new String[]{"scim","clients"})));
		Map<String, String> azParameters = new HashMap<String, String>(authorizationRequest.getAuthorizationParameters());
		azParameters.put("grant_type", "client_credentials");
		authorizationRequest.setAuthorizationParameters(azParameters);

		OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest, null);

		OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
		OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

		assertEquals(AuthorityUtils.commaSeparatedStringToAuthorityList("update"), loadedAuthentication.getAuthorities());
		assertEquals("client", loadedAuthentication.getName());
		assertEquals("client", loadedAuthentication.getPrincipal());
		assertNull(loadedAuthentication.getDetails());

		assertNull(loadedAuthentication.getUserAuthentication());
	}
}
