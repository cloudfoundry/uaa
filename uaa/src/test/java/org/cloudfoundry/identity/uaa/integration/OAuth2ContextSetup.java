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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.internal.AssumptionViolatedException;
import org.junit.internal.runners.statements.RunBefores;
import org.junit.rules.TestWatchman;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.junit.runners.model.TestClass;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestOperations;
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

	private static Log logger = LogFactory.getLog(OAuth2ContextSetup.class);

	private OAuth2ProtectedResourceDetails resource;

	private OAuth2RestTemplate client;

	private Map<String, String> parameters = new LinkedHashMap<String, String>();

	private final ServerRunning server;

	private final TestAccounts testAccounts;
	
	public static OAuth2ContextSetup standard(ServerRunning server, TestAccounts testAccounts) {
		return new OAuth2ContextSetup(server, testAccounts);
	}

	private OAuth2ContextSetup(ServerRunning server, TestAccounts testAccounts) {
		this(server, testAccounts, Collections.<String, String> emptyMap());
	}

	private OAuth2ContextSetup(ServerRunning server, TestAccounts testAccounts, Map<String, String> parameters) {
		this.server = server;
		this.testAccounts = testAccounts;
		this.parameters = parameters;
	}

	private OAuth2RestTemplate createRestTemplate(OAuth2ProtectedResourceDetails resource) {
		OAuth2RestTemplate client = new OAuth2RestTemplate(resource);
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

	@Override
	public Statement apply(Statement base, FrameworkMethod method, Object target) {
		initializeIfNecessary(method, target);
		return super.apply(base, method, target);
	}

	@Override
	public void starting(FrameworkMethod method) {
		if (resource != null) {
			logger.info("Starting OAuth2 context for: " + resource);
			AccessTokenRequest request = new AccessTokenRequest();
			request.setAll(parameters);
			OAuth2ClientContext context = new OAuth2ClientContext(request);
			OAuth2ClientContextHolder.setContext(context);
			server.setRestTemplate(client);
		}
	}

	@Override
	public void finished(FrameworkMethod method) {
		if (resource != null) {
			logger.info("Ending OAuth2 context for: " + resource);
			OAuth2ClientContextHolder.clearContext();
		}
	}

	private void initializeIfNecessary(FrameworkMethod method, final Object target) {
		final TestClass testClass = new TestClass(target.getClass());
		OAuth2ContextConfiguration contextConfiguration = findOAuthContextConfiguration(method, testClass);
		if (contextConfiguration == null) {
			// Nothing to do
			return;
		}
		this.resource = creatResource(contextConfiguration);
		this.client = createRestTemplate(resource);
		final List<FrameworkMethod> befores = testClass.getAnnotatedMethods(BeforeOAuth2Context.class);
		if (!befores.isEmpty()) {
			logger.debug("Running @BeforeOAuth2Context methods");
			setup(new OAuth2ContextSetupCallback() {
				@Override
				public void doWithRestOperations(RestOperations client) {
					try {
						new RunBefores(new Statement() {
							public void evaluate() {
							}
						}, befores, target).evaluate();
					}
					catch (AssumptionViolatedException e) {
						throw e;
					}
					catch (Throwable e) {
						Assert.assertThat(e, CoreMatchers.not(CoreMatchers.anything()));
					}
				}
			});
		}
	}

	public void setParameters(Map<String, String> parameters) {
		this.parameters = parameters;
	}

	public OAuth2ProtectedResourceDetails getResource() {
		return resource;
	}

	public RestTemplate getRestTemplate() {
		return client;
	}

	private OAuth2ProtectedResourceDetails creatResource(OAuth2ContextConfiguration contextLoader) {
		if (contextLoader.value() == OAuth2ContextConfiguration.GrantType.CLIENT_CREDENTIALS) {
			return testAccounts.getClientCredentialsResource("scim", "scim", "scimsecret");
		}
		if (contextLoader.value() == OAuth2ContextConfiguration.GrantType.IMPLICIT) {
			return testAccounts.getImplicitResource("vmc", "vmc", "marissa", "koala");
		}
		if (contextLoader.value() == OAuth2ContextConfiguration.GrantType.RESOURCE_OWNER) {
			return testAccounts.getResourceOwnerPasswordResource("test", "app", "appclientsecret", "marissa", "koala");
		}
		throw new IllegalStateException("Should not happen: no such type " + contextLoader.value());
	}

	private OAuth2ContextConfiguration findOAuthContextConfiguration(FrameworkMethod method, TestClass testClass) {
		if (testClass.getJavaClass().isAnnotationPresent(OAuth2ContextConfiguration.class)) {
			return testClass.getJavaClass().getAnnotation(OAuth2ContextConfiguration.class);
		}
		return method.getAnnotation(OAuth2ContextConfiguration.class);
	}

	private void setup(OAuth2ContextSetupCallback callback) {

		ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
		resource.setClientId("scim");
		resource.setClientSecret("scimsecret");
		resource.setId("scim");
		resource.setScope(Arrays.asList("read", "write", "password"));
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(server.getUrl("/oauth/token"));
		OAuth2RestTemplate savedContextClient = client;
		client = createRestTemplate(resource);

		logger.info("Setting up OAuth2 context for: " + resource);
		RestTemplate savedServerClient = server.getRestTemplate();
		OAuth2ClientContext savedContext = OAuth2ClientContextHolder.getContext();
		AccessTokenRequest request = new AccessTokenRequest();
		request.setAll(parameters);
		OAuth2ClientContext context = new OAuth2ClientContext(request);
		OAuth2ClientContextHolder.setContext(context);
		server.setRestTemplate(client);

		try {
			callback.doWithRestOperations(client);
		}
		finally {
			logger.info("Tearing down OAuth2 context for: " + resource);
			OAuth2ClientContextHolder.clearContext();
			OAuth2ClientContextHolder.setContext(savedContext);
			server.setRestTemplate(savedServerClient);
			client = savedContextClient;
		}

	}

}
