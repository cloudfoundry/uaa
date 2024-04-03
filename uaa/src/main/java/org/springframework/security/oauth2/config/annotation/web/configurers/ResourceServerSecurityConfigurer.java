package org.springframework.security.oauth2.config.annotation.web.configurers;

import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.TokenExtractor;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.oauth.provider.token.DefaultTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.InMemoryTokenStore;
import org.cloudfoundry.identity.uaa.oauth.provider.token.ResourceServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.TokenStore;
import org.springframework.http.MediaType;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;

public final class ResourceServerSecurityConfigurer extends
		SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

	private AccessDeniedHandler accessDeniedHandler = new OAuth2AccessDeniedHandler();

	private OAuth2AuthenticationProcessingFilter resourcesServerFilter;

	private AuthenticationManager authenticationManager;

	private AuthenticationEventPublisher eventPublisher = null;

	private ResourceServerTokenServices resourceTokenServices;

	private TokenStore tokenStore = new InMemoryTokenStore();

	private String resourceId = "oauth2-resource";

	private SecurityExpressionHandler<FilterInvocation> expressionHandler = new OAuth2WebSecurityExpressionHandler();

	private TokenExtractor tokenExtractor;

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	private boolean stateless = true;

	public ResourceServerSecurityConfigurer() {
		resourceId(resourceId);
	}

	private ClientDetailsService clientDetails() {
		return getBuilder().getSharedObject(ClientDetailsService.class);
	}

	public TokenStore getTokenStore() {
		return tokenStore;
	}

	/**
	 * Flag to indicate that only token-based authentication is allowed on these resources.
	 * @param stateless the flag value (default true)
	 * @return this (for fluent builder)
	 */
	public ResourceServerSecurityConfigurer stateless(boolean stateless) {
		this.stateless = stateless;
		return this;
	}

	public ResourceServerSecurityConfigurer authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		return this;
	}

	public ResourceServerSecurityConfigurer accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		this.accessDeniedHandler = accessDeniedHandler;
		return this;
	}

	public ResourceServerSecurityConfigurer tokenStore(TokenStore tokenStore) {
		Assert.state(tokenStore != null, "TokenStore cannot be null");
		this.tokenStore = tokenStore;
		return this;
	}

	public ResourceServerSecurityConfigurer eventPublisher(AuthenticationEventPublisher eventPublisher) {
		Assert.state(eventPublisher != null, "AuthenticationEventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
		return this;
	}

	public ResourceServerSecurityConfigurer expressionHandler(
			SecurityExpressionHandler<FilterInvocation> expressionHandler) {
		Assert.state(expressionHandler != null, "SecurityExpressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
		return this;
	}

	public ResourceServerSecurityConfigurer tokenExtractor(TokenExtractor tokenExtractor) {
		Assert.state(tokenExtractor != null, "TokenExtractor cannot be null");
		this.tokenExtractor = tokenExtractor;
		return this;
	}

	/**
	 * Sets a custom {@link AuthenticationDetailsSource} to use as a source
	 * of authentication details. The default is {@link OAuth2AuthenticationDetailsSource}.
	 *
	 * @param authenticationDetailsSource the custom {@link AuthenticationDetailsSource} to use
	 * @return {@link ResourceServerSecurityConfigurer} for additional customization
	 */
	public ResourceServerSecurityConfigurer authenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.state(authenticationDetailsSource != null, "AuthenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
		return this;
	}

	public ResourceServerSecurityConfigurer authenticationManager(AuthenticationManager authenticationManager) {
		Assert.state(authenticationManager != null, "AuthenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
		return this;
	}

	public ResourceServerSecurityConfigurer tokenServices(ResourceServerTokenServices tokenServices) {
		Assert.state(tokenServices != null, "ResourceServerTokenServices cannot be null");
		this.resourceTokenServices = tokenServices;
		return this;
	}

	@Override
	public void init(HttpSecurity http) throws Exception {
		registerDefaultAuthenticationEntryPoint(http);
	}

	@SuppressWarnings("unchecked")
	private void registerDefaultAuthenticationEntryPoint(HttpSecurity http) {
		ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling = http
				.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}
		ContentNegotiationStrategy contentNegotiationStrategy = http.getSharedObject(ContentNegotiationStrategy.class);
		if (contentNegotiationStrategy == null) {
			contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
		}
		MediaTypeRequestMatcher preferredMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy,
				MediaType.APPLICATION_ATOM_XML, MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
				MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML, MediaType.MULTIPART_FORM_DATA,
				MediaType.TEXT_XML);
		preferredMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		exceptionHandling.defaultAuthenticationEntryPointFor(postProcess(authenticationEntryPoint), preferredMatcher);
	}

	public ResourceServerSecurityConfigurer resourceId(String resourceId) {
		this.resourceId = resourceId;
		if (authenticationEntryPoint instanceof OAuth2AuthenticationEntryPoint) {
			((OAuth2AuthenticationEntryPoint) authenticationEntryPoint).setRealmName(resourceId);
		}
		return this;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {

		AuthenticationManager oauthAuthenticationManager = oauthAuthenticationManager(http);
		resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();
		resourcesServerFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
		resourcesServerFilter.setAuthenticationManager(oauthAuthenticationManager);
		if (eventPublisher != null) {
			resourcesServerFilter.setAuthenticationEventPublisher(eventPublisher);
		}
		if (tokenExtractor != null) {
			resourcesServerFilter.setTokenExtractor(tokenExtractor);
		}
		if (authenticationDetailsSource != null) {
			resourcesServerFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		}
		resourcesServerFilter = postProcess(resourcesServerFilter);
		resourcesServerFilter.setStateless(stateless);

		// @formatter:off
		http
			.authorizeRequests().expressionHandler(expressionHandler)
		.and()
			.addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
			.exceptionHandling()
				.accessDeniedHandler(accessDeniedHandler)
				.authenticationEntryPoint(authenticationEntryPoint);
		// @formatter:on
	}

	private AuthenticationManager oauthAuthenticationManager(HttpSecurity http) {
		OAuth2AuthenticationManager oauthAuthenticationManager = new OAuth2AuthenticationManager();
		if (authenticationManager != null) {
			if (authenticationManager instanceof OAuth2AuthenticationManager) {
				oauthAuthenticationManager = (OAuth2AuthenticationManager) authenticationManager;
			}
			else {
				return authenticationManager;
			}
		}
		oauthAuthenticationManager.setResourceId(resourceId);
		oauthAuthenticationManager.setTokenServices(resourceTokenServices(http));
		oauthAuthenticationManager.setClientDetailsService(clientDetails());
		return oauthAuthenticationManager;
	}

	private ResourceServerTokenServices resourceTokenServices(HttpSecurity http) {
		tokenServices(http);
		return this.resourceTokenServices;
	}

	private ResourceServerTokenServices tokenServices(HttpSecurity http) {
		if (resourceTokenServices != null) {
			return resourceTokenServices;
		}
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setTokenStore(tokenStore());
		tokenServices.setSupportRefreshToken(true);
		tokenServices.setClientDetailsService(clientDetails());
		this.resourceTokenServices = tokenServices;
		return tokenServices;
	}

	private TokenStore tokenStore() {
		Assert.state(tokenStore != null, "TokenStore cannot be null");
		return this.tokenStore;
	}

	public AccessDeniedHandler getAccessDeniedHandler() {
		return this.accessDeniedHandler;
	}

}
