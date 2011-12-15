/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.integration;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Arrays;
import java.util.List;

import org.junit.rules.TestWatchman;
import org.junit.runners.model.FrameworkMethod;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * <p>
 * A rule that sets up an OAuth2 context for tests.
 * </p>
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2ContextSetup extends TestWatchman {

	private OAuth2ProtectedResourceDetails resource;

	private OAuth2RestTemplate client;

	private AccessTokenProviderChain accessTokenProvider;

	public static OAuth2ContextSetup defaultClientCredentials(ServerRunning server) {
		return clientCredentials(server, Arrays.asList("read,write,password"));
	}

	public static OAuth2ContextSetup clientCredentials(ServerRunning server, List<String> scopes) {
		ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
		resource.setClientId("scim");
		resource.setClientSecret("scimsecret");
		resource.setId("scim");
		resource.setScope(scopes);
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(server.getUrlFromRoot("/oauth/token"));
		return new OAuth2ContextSetup(server, resource);
	}

	public static OAuth2ContextSetup resourceOwner(ServerRunning server, String username, String password) {
		return resourceOwner(server, username, password, Arrays.asList("read", "openid"));
	}

	public static OAuth2ContextSetup resourceOwner(ServerRunning server, String username, String password, List<String> scopes) {
		ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();
		resource.setClientId("app");
		resource.setClientSecret("appclientsecret");
		resource.setId("app");
		resource.setScope(scopes);
		resource.setUsername(username);
		resource.setPassword(password);
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(server.getUrlFromRoot("/oauth/token"));
		return new OAuth2ContextSetup(server, resource);
	}

	public OAuth2ContextSetup(ServerRunning server, OAuth2ProtectedResourceDetails resource) {
		this.resource = resource;
		client = new OAuth2RestTemplate(resource);
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
		server.setRestTemplate(client);
		this.resource = resource;
		this.accessTokenProvider = new AccessTokenProviderChain(Arrays.<AccessTokenProvider> asList(
				new ClientCredentialsAccessTokenProvider(), new ResourceOwnerPasswordAccessTokenProvider()));
	}

	@Override
	public void starting(FrameworkMethod method) {
		OAuth2ClientContext context = new OAuth2ClientContext();
		OAuth2ClientContextHolder.setContext(context);
		AccessTokenRequest request = new AccessTokenRequest();
		try {
			context.addAccessToken(resource, accessTokenProvider.obtainAccessToken(resource, request));
		}
		catch (UserRedirectRequiredException e) {
			throw new IllegalStateException("Client credentials not supported?", e);
		}
	}

	@Override
	public void finished(FrameworkMethod method) {
		OAuth2ClientContextHolder.clearContext();
	}

	public OAuth2ProtectedResourceDetails getResource() {
		return resource;
	}

	public RestTemplate getRestTemplate() {
		return client;
	}

}
