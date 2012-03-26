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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;

/**
 * @author Dave Syer
 * 
 */
public class TestAccounts {

	private static final Log logger = LogFactory.getLog(TestAccounts.class);

	private Environment environment = TestProfileEnvironment.getEnvironment();

	private ServerRunning server;

	private TestAccounts(ServerRunning server) {
		this.server = server;
	}

	public static TestAccounts standard(ServerRunning server) {
		return new TestAccounts(server);
	}

	public String getUserName() {
		return environment.getProperty("uaa.test.username", "marissa");
	}

	public String getPassword() {
		return environment.getProperty("uaa.test.password", "koala");
	}

	public String getEmail() {
		String value = getUserName();
		if (!value.contains("@")) {
			value = value + "@test.org";
		}
		return environment.getProperty("uaa.test.email", value);
	}

	public String getAdminClientId() {
		return environment.getProperty("UAA_ADMIN_CLIENT_ID",
				environment.getProperty("oauth.clients.admin.id", "admin"));
	}

	public String getAdminClientSecret() {
		return environment.getProperty("UAA_ADMIN_CLIENT_SECRET",
				environment.getProperty("oauth.clients.admin.secret", "adminclientsecret"));
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
		return getAuthorizationHeader("batch", "batch", "batchsecret");
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

	public OAuth2ProtectedResourceDetails getClientCredentialsResource(String prefix, String defaultUsername,
			String defaultPassword) {
		ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
		String username = environment.getProperty(prefix + ".id", defaultUsername);
		String password = environment.getProperty(prefix + ".secret", defaultPassword);
		resource.setClientId(username);
		resource.setClientSecret(password);
		resource.setId(prefix);
		resource.setScope(Arrays.asList("read", "write", "password"));
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(server.getUrl("/oauth/token"));
		return resource;
	}

	public OAuth2ProtectedResourceDetails getImplicitResource(String prefix, String defaultClientId, String defaultUsername, String defaultPassword) {
		ImplicitResourceDetails resource = new ImplicitResourceDetails();
		String clientId = environment.getProperty(prefix + ".id", defaultClientId);
		resource.setClientId(clientId);
		resource.setId(clientId);
		Map<String, String> parameters = new LinkedHashMap<String, String>();
		String username = environment.getProperty(prefix + ".username", defaultUsername);
		String password = environment.getProperty(prefix + ".password", defaultPassword);
		parameters.put("credentials", String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password));
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(server.getUrl("/oauth/authorize"));
		resource.setScope(Arrays.asList("read", "password"));
		resource.setPreEstablishedRedirectUri("http://uaa.cloudfoundry.com/redirect/vmc");
		return resource;
	}

	public OAuth2ProtectedResourceDetails getResourceOwnerPasswordResource(String prefix, String defaultClientId, String defaultClientSecret, String defaultUsername, String defaultPassword) {
		ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();
		String clientId = environment.getProperty(prefix + ".id", defaultClientId);
		String clientSceret = environment.getProperty(prefix + ".secret", defaultClientSecret);
		resource.setClientId(clientId);
		resource.setClientSecret(clientSceret);
		resource.setId(clientId);
		resource.setScope(Arrays.asList("read", "openid"));
		Map<String, String> parameters = new LinkedHashMap<String, String>();
		String username = environment.getProperty(prefix + ".username", defaultUsername);
		String password = environment.getProperty(prefix + ".password", defaultPassword);
		parameters.put("username", username);
		parameters.put("password", password);
		resource.setUsername(username);
		resource.setPassword(password);
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(server.getUrl("/oauth/token"));
		return resource;
	}

}
