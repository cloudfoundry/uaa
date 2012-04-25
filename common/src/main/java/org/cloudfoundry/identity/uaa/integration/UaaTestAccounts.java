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
package org.cloudfoundry.identity.uaa.integration;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Name;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.StringUtils;

/**
 * UAA specific test account data externalized with {@link TestProfileEnvironment}.
 * 
 * @author Dave Syer
 * 
 */
public class UaaTestAccounts implements TestAccounts {

	/**
	 * Default password for a user if strong passwords are required
	 */
	private static final String DEFAULT_STRING_PASSWORD = "dr0wssaPH@ck";

	/**
	 * Default password for a user if strong passwords are not required
	 */
	public static final String DEFAULT_WEAK_PASSWORD = "koala";

	/**
	 * Default username for a user account to use for testing
	 */
	public static final String DEFAULT_USERNAME = "marissa";

	private static final Log logger = LogFactory.getLog(UaaTestAccounts.class);

	private Environment environment = TestProfileEnvironment.getEnvironment();

	private UrlHelper server;

	private static Map<String, OAuth2ProtectedResourceDetails> clientDetails = new HashMap<String, OAuth2ProtectedResourceDetails>();

	private UaaTestAccounts(UrlHelper server) {
		this.server = server;
	}

	public static UaaTestAccounts standard(UrlHelper server) {
		return new UaaTestAccounts(server);
	}

	public String getUserName() {
		return environment.getProperty("uaa.test.username", DEFAULT_USERNAME);
	}

	public String getPassword() {
		String defaultPassword = DEFAULT_WEAK_PASSWORD;
		if (environment.getActiveProfiles().length > 0) {
			// except in the default profile the password validator will block "koala"
			defaultPassword = DEFAULT_STRING_PASSWORD;
		}
		return environment.getProperty("uaa.test.password", defaultPassword);
	}

	public String getEmail() {
		String value = getUserName();
		if (!value.contains("@")) {
			value = value + "@test.org";
		}
		return environment.getProperty("uaa.test.email", value);
	}

	public ScimUser getUser() {
		ScimUser user = new ScimUser();
		user.setUserName(getUserName());
		user.addEmail(getEmail());
		ReflectionTestUtils.setField(user, "password", getPassword());
		Name name = new Name();
		name.setGivenName("Test");
		name.setFamilyName("User");
		user.setName(name);
		return user;
	}

	public String getAdminClientId() {
		return environment.getProperty("UAA_ADMIN_CLIENT_ID",
				environment.getProperty("oauth.clients.admin.id", "admin"));
	}

	public String getAdminClientSecret() {
		return environment.getProperty("UAA_ADMIN_CLIENT_SECRET",
				environment.getProperty("oauth.clients.admin.secret", "adminsecret"));
	}

	/**
	 * @return true if this Spring profile is enabled on the server
	 */
	public boolean isProfileActive(String profile) {
		List<String> profiles = Arrays.asList(environment.getActiveProfiles());
		logger.debug(String.format("Checking for %s profile in: [%s]", profile, environment));
		return profile != null && profiles.contains(profile);
	}

	public String getVarzAuthorizationHeader() {
		return getAuthorizationHeader("varz", "varz", "varzclientsecret");
	}

	public String getBatchAuthorizationHeader() {
		return getAuthorizationHeader("batch", "batch_user", "batch_password");
	}

	public String getAuthorizationHeader(String prefix, String defaultUsername, String defaultPassword) {
		String username = environment.getProperty(prefix + ".username", defaultUsername);
		String password = environment.getProperty(prefix + ".password", defaultPassword);
		return getAuthorizationHeader(username, password);
	}

	public String getAuthorizationHeader(String username, String password) {
		String credentials = String.format("%s:%s", username, password);
		return String.format("Basic %s", new String(Base64.encode(credentials.getBytes())));
	}

	public String getJsonCredentials(String prefix, String defaultUsername, String defaultPassword) {
		String username = environment.getProperty(prefix + ".username", defaultUsername);
		String password = environment.getProperty(prefix + ".password", defaultPassword);
		return getJsonCredentials(username, password);
	}

	public String getJsonCredentials(String username, String password) {
		String credentials = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
		return credentials;
	}

	public ClientCredentialsResourceDetails getAdminClientCredentialsResource() {
		return getClientCredentialsResource(getAdminClientId(), getAdminClientSecret());
	}

	public ClientCredentialsResourceDetails getClientCredentialsResource(String prefix, String defaultClientId,
			String defaultClientSecret) {
		if (clientDetails.containsKey(prefix)) {
			return (ClientCredentialsResourceDetails) clientDetails.get(prefix);
		}
		String clientId = environment.getProperty(prefix + ".id", defaultClientId);
		String clientSecret = environment.getProperty(prefix + ".secret", defaultClientSecret);
		ClientCredentialsResourceDetails resource = getClientCredentialsResource(clientId, clientSecret);
		clientDetails.put(prefix, resource);
		return resource;
	}

	public ClientCredentialsResourceDetails getClientCredentialsResource(String clientId, String clientSecret) {
		ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
		resource.setClientId(clientId);
		resource.setClientSecret(clientSecret);
		resource.setId(clientId);
		resource.setScope(Arrays.asList("read", "write", "password"));
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(server.getAccessTokenUri());
		return resource;
	}

	public ImplicitResourceDetails getImplicitResource(String clientPrefix, String defaultClientId,
			String defaultRedirectUri, String username, String password) {
		ImplicitResourceDetails resource = new ImplicitResourceDetails();
		String clientId = environment.getProperty(clientPrefix + ".id", defaultClientId);
		resource.setClientId(clientId);
		resource.setId(clientId);
		Map<String, String> parameters = new LinkedHashMap<String, String>();
		parameters.put("credentials", String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password));
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(server.getAuthorizationUri());
		resource.setScope(Arrays.asList("read", "password", "openid"));
		String redirectUri = environment.getProperty(clientPrefix + ".redirect-uri", defaultRedirectUri);
		resource.setPreEstablishedRedirectUri(redirectUri);
		return resource;
	}

	public ResourceOwnerPasswordResourceDetails getResourceOwnerPasswordResource(String clientPrefix,
			String defaultClientId, String defaultClientSecret, String username, String password) {
		return getResourceOwnerPasswordResource(new String[] { "read", "openid" }, clientPrefix, defaultClientId,
				defaultClientSecret, username, password);
	}

	public ResourceOwnerPasswordResourceDetails getResourceOwnerPasswordResource(String[] scope, String clientPrefix,
			String defaultClientId, String defaultClientSecret, String username, String password) {
		String clientId = environment.getProperty(clientPrefix + ".id", defaultClientId);
		String clientSecret = environment.getProperty(clientPrefix + ".secret", defaultClientSecret);
		return getResourceOwnerPasswordResource(scope, clientId, clientSecret, username, password);
	}

	@Override
	public ResourceOwnerPasswordResourceDetails getResourceOwnerPasswordResource(String[] scope, String clientId,
			String clientSecret, String username, String password) {

		ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();
		resource.setClientId(clientId);
		resource.setClientSecret(clientSecret);
		resource.setId(clientId);
		resource.setScope(Arrays.asList(scope));
		Map<String, String> parameters = new LinkedHashMap<String, String>();
		parameters.put("username", username);
		parameters.put("password", password);
		resource.setUsername(username);
		resource.setPassword(password);
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(server.getAccessTokenUri());
		return resource;
	}

	public ClientDetails getClientDetails(String prefix, BaseClientDetails defaults) {
		String clientId = environment.getProperty(prefix + ".id", defaults.getClientId());
		String clientSecret = environment.getProperty(prefix + ".secret", defaults.getClientSecret());
		String resourceIds = environment.getProperty(prefix + ".resource-ids",
				StringUtils.collectionToCommaDelimitedString(defaults.getResourceIds()));
		String scopes = environment.getProperty(prefix + ".scope",
				StringUtils.collectionToCommaDelimitedString(defaults.getScope()));
		String grantTypes = environment.getProperty(prefix + ".authorized-grant-types",
				StringUtils.collectionToCommaDelimitedString(defaults.getAuthorizedGrantTypes()));
		String authorities = environment.getProperty(prefix + ".authorities",
				StringUtils.collectionToCommaDelimitedString(defaults.getAuthorities()));
		String redirectUris = environment.getProperty(prefix + ".redirect-uri",
				StringUtils.collectionToCommaDelimitedString(defaults.getRegisteredRedirectUri()));
		BaseClientDetails result = new BaseClientDetails(resourceIds, scopes, grantTypes, authorities, redirectUris);
		result.setClientId(clientId);
		result.setClientSecret(clientSecret);
		return result;
	}

	public ClientCredentialsResourceDetails getDefaultClientCredentialsResource() {
		return getClientCredentialsResource("oauth.clients.scim", "scim", "scimsecret");
	}

	public ResourceOwnerPasswordResourceDetails getDefaultResourceOwnerPasswordResource() {
		return getResourceOwnerPasswordResource("oauth.clients.app", "app", "appclientsecret", getUserName(),
				getPassword());
	}

	public ImplicitResourceDetails getDefaultImplicitResource() {
		return getImplicitResource("oauth.clients.vmc", "vmc", "http://uaa.cloudfoundry.com/redirect/vmc",
				getUserName(), getPassword());
	}

	public String getCloudControllerUrl() {
		return environment.getProperty("uaa.test.cloud_controller.url", "http://localhost:8080/api");
	}

}
