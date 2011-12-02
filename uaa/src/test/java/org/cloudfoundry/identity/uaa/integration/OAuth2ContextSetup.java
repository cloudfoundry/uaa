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

import java.util.Arrays;

import org.junit.rules.TestWatchman;
import org.junit.runners.model.FrameworkMethod;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
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

	public OAuth2ContextSetup(ServerRunning server) {
		ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
		resource.setClientId("www");
		resource.setClientSecret("wwwclientsecret");
		resource.setId("openid");
		resource.setScope(Arrays.asList("read"));
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(server.getUrlFromRoot("/oauth/token"));
		server.setRestTemplate(new OAuth2RestTemplate(resource));
		this.resource = resource;
	}

	@Override
	public void starting(FrameworkMethod method) {
		OAuth2ClientContext context = new OAuth2ClientContext();
		OAuth2ClientContextHolder.setContext(context);
		AccessTokenRequest request = new AccessTokenRequest();
		try {
			context.addAccessToken(resource,
					new ClientCredentialsAccessTokenProvider().obtainAccessToken(resource, request));
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
		return new OAuth2RestTemplate(resource);
	}

}
