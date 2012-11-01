/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.users.ScimUser;
import org.junit.rules.TestWatchman;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.context.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.Assert;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestOperations;

/**
 * @author Dave Syer
 * 
 */
public class TestAccountSetup extends TestWatchman {

	private static Log logger = LogFactory.getLog(TestAccountSetup.class);

	private final UrlHelper serverRunning;

	private final UaaTestAccounts testAccounts;

	private static boolean initialized = false;

	private TestAccountSetup(UrlHelper serverRunning, UaaTestAccounts testAccounts) {
		this.serverRunning = serverRunning;
		this.testAccounts = testAccounts;
	}

	public static TestAccountSetup standard(UrlHelper serverRunning, UaaTestAccounts testAccounts) {
		return new TestAccountSetup(serverRunning, testAccounts);
	}

	@Override
	public Statement apply(Statement base, FrameworkMethod method, Object target) {
		initializeIfNecessary(method, target);
		return super.apply(base, method, target);
	}

	private void initializeIfNecessary(FrameworkMethod method, Object target) {
		// Cache statically to save time on a test suite
		if (!initialized) {
			OAuth2ProtectedResourceDetails resource = testAccounts.getAdminClientCredentialsResource();
			logger.info("Checking user account context for server=" + resource.getAccessTokenUri());
			OAuth2RestTemplate client = createRestTemplate(resource, new DefaultAccessTokenRequest());
			if (!scimClientExists(client)) {
				createScimClient(client);
			}
			if (!appClientExists(client)) {
				createAppClient(client);
			}
			if (!vmcClientExists(client)) {
				createVmcClient(client);
			}
			if (!tokenClientExists(client)) {
				createTokenClient(client);
			}
			resource = testAccounts.getClientCredentialsResource("oauth.clients.scim", "scim", "scimsecret");
			client = createRestTemplate(resource, new DefaultAccessTokenRequest());
			if (!userAccountExists(client)) {
				createUserAccount(client);
			}
			initialized = true;
		}
	}

	private void createTokenClient(RestOperations client) {
		BaseClientDetails clientDetails = new BaseClientDetails("token", "tokens", "tokens.read,tokens.write",
				"authorization_code,password", "tokens.read,tokens.write");
		clientDetails.setClientSecret("tokenclientsecret");
		createClient(client, testAccounts.getClientDetails("oauth.clients.token", clientDetails));
	}

	private void createVmcClient(RestOperations client) {
		BaseClientDetails clientDetails = new BaseClientDetails("vmc", "cloud_controller,openid,password",
				"openid,cloud_controller.read,password.write,tokens.read,tokens.write", "implicit", "uaa.none",
				"https://uaa.cloudfoundry.com/redirect/vmc");
		createClient(client, testAccounts.getClientDetails("oauth.clients.vmc", clientDetails));
	}

	private void createScimClient(RestOperations client) {
		BaseClientDetails clientDetails = new BaseClientDetails("scim", "none", "uaa.none", "client_credentials",
				"scim.read,scim.write,password.write,tokens.read,tokens.write");
		clientDetails.setClientSecret("scimsecret");
		createClient(client, testAccounts.getClientDetails("oauth.clients.scim", clientDetails));
	}

	private void createAppClient(RestOperations client) {
		BaseClientDetails clientDetails = new BaseClientDetails("app", "none",
				"cloud_controller.read,openid,password.write", "password,authorization_code,refresh_token",
				"uaa.resource");
		clientDetails.setClientSecret("appclientsecret");
		createClient(client, testAccounts.getClientDetails("oauth.clients.app", clientDetails));
	}

	private void createClient(RestOperations client, ClientDetails clientDetails) {
		ResponseEntity<String> response = client.postForEntity(serverRunning.getClientsUri(), clientDetails,
				String.class);
		assertEquals(HttpStatus.CREATED, response.getStatusCode());
	}

	private boolean clientExists(RestOperations client, OAuth2ProtectedResourceDetails resource) {
		ResponseEntity<String> response = client.getForEntity(
				serverRunning.getClientsUri() + "/" + resource.getClientId(), String.class);
		return response != null && response.getStatusCode() == HttpStatus.OK;
	}

	private boolean vmcClientExists(RestOperations client) {
		return clientExists(client, testAccounts.getClientCredentialsResource("oauth.clients.vmc", "vmc", null));
	}

	private boolean tokenClientExists(RestOperations client) {
		return clientExists(client,
				testAccounts.getClientCredentialsResource("oauth.clients.token", "token", "tokenclientsecret"));
	}

	private boolean scimClientExists(RestOperations client) {
		return clientExists(client,
				testAccounts.getClientCredentialsResource("oauth.clients.scim", "scim", "scimsecret"));
	}

	private boolean appClientExists(RestOperations client) {
		return clientExists(client,
				testAccounts.getClientCredentialsResource("oauth.clients.app", "app", "appclientsecret"));
	}

	private void createUserAccount(RestOperations client) {
		ScimUser user = testAccounts.getUser();
		ResponseEntity<ScimUser> response = client.postForEntity(serverRunning.getUserUri(), user, ScimUser.class);
		Assert.state(response.getStatusCode() == HttpStatus.CREATED);
	}

	private boolean userAccountExists(RestOperations client) {
		Map<?, ?> map = client.getForObject(
				serverRunning.getUsersUri() + "?filter=userName eq '" + testAccounts.getUserName() + "'", Map.class);
		Integer count = (Integer) map.get("totalResults");
		if (count == null) {
			throw new IllegalStateException("Null response from user exists query: " + map);
		}
		if (count > 1) {
			throw new IllegalStateException("More than one user already exists with the test user name.");
		}
		if (count == 1) {
			return true;
		}
		return false;
	}

	private OAuth2RestTemplate createRestTemplate(OAuth2ProtectedResourceDetails resource,
			AccessTokenRequest accessTokenRequest) {
		OAuth2ClientContext context = new DefaultOAuth2ClientContext(accessTokenRequest);
		OAuth2RestTemplate client = new OAuth2RestTemplate(resource, context);
		client.setRequestFactory(new SimpleClientHttpRequestFactory() {
			@Override
			protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
				super.prepareConnection(connection, httpMethod);
				connection.setInstanceFollowRedirects(false);
			}
		});
		client.setErrorHandler(new ResponseErrorHandler() {
			// Pass errors through in response entity for status code analysis
			public boolean hasError(ClientHttpResponse response) throws IOException {
				return false;
			}

			public void handleError(ClientHttpResponse response) throws IOException {
			}
		});
		List<HttpMessageConverter<?>> list = new ArrayList<HttpMessageConverter<?>>();
		list.add(new StringHttpMessageConverter());
		list.add(new MappingJacksonHttpMessageConverter());
		client.setMessageConverters(list);
		return client;
	}

}
