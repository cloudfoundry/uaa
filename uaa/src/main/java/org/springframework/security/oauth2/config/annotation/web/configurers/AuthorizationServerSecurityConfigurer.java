package org.springframework.security.oauth2.config.annotation.web.configurers;

import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class AuthorizationServerSecurityConfigurer extends
		SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	private AuthenticationEntryPoint authenticationEntryPoint;

	private AccessDeniedHandler accessDeniedHandler = new OAuth2AccessDeniedHandler();

	private PasswordEncoder passwordEncoder; // for client secrets

	private String realm = "oauth2/client";

	private boolean allowFormAuthenticationForClients = false;

	private String tokenKeyAccess = "denyAll()";

	private String checkTokenAccess = "denyAll()";

	private boolean sslOnly = false;

	/**
	 * Custom authentication filters for the TokenEndpoint. Filters will be set upstream of the default
	 * BasicAuthenticationFilter.
	 */
	private List<Filter> tokenEndpointAuthenticationFilters = new ArrayList<Filter>();
	
	private List<AuthenticationProvider> authenticationProviders = new ArrayList<AuthenticationProvider>();
	
	private AuthenticationEventPublisher authenticationEventPublisher;
	
	public AuthorizationServerSecurityConfigurer sslOnly() {
		this.sslOnly = true;
		return this;
	}

	public AuthorizationServerSecurityConfigurer allowFormAuthenticationForClients() {
		this.allowFormAuthenticationForClients = true;
		return this;
	}

	public AuthorizationServerSecurityConfigurer realm(String realm) {
		this.realm = realm;
		return this;
	}

	public AuthorizationServerSecurityConfigurer passwordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
		return this;
	}

	public AuthorizationServerSecurityConfigurer authenticationEntryPoint(
			AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		return this;
	}

	public AuthorizationServerSecurityConfigurer accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		this.accessDeniedHandler = accessDeniedHandler;
		return this;
	}

	/**
	 * Authentication provider(s) to use with the {@link AuthenticationManager}.
	 * Adding an authentication provider here will replace the default {@link DaoAuthenticationProvider}.
	 * 
	 * @param authenticationProvider the authentication provider to add
	 */	
	public AuthorizationServerSecurityConfigurer addAuthenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider must not be null");
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}
	
    /**
     * {@link AuthenticationEventPublisher} to use with the {@link AuthenticationManager}.
     * 
     * @param authenticationEventPublisher the {@link AuthenticationEventPublisher} to use
     */ 
    public AuthorizationServerSecurityConfigurer authenticationEventPublisher(AuthenticationEventPublisher authenticationEventPublisher) {
        Assert.notNull(authenticationEventPublisher, "authenticationEventPublisher must not be null");
        this.authenticationEventPublisher = authenticationEventPublisher;
        return this;
    }	

	public AuthorizationServerSecurityConfigurer tokenKeyAccess(String tokenKeyAccess) {
		this.tokenKeyAccess = tokenKeyAccess;
		return this;
	}

	public AuthorizationServerSecurityConfigurer checkTokenAccess(String checkTokenAccess) {
		this.checkTokenAccess = checkTokenAccess;
		return this;
	}

	public String getTokenKeyAccess() {
		return tokenKeyAccess;
	}

	public String getCheckTokenAccess() {
		return checkTokenAccess;
	}

	@Override
	public void init(HttpSecurity http) throws Exception {
		registerDefaultAuthenticationEntryPoint(http);
		AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
		if (authenticationEventPublisher != null) {
		    builder.authenticationEventPublisher(authenticationEventPublisher);
		}
		if (authenticationProviders.isEmpty()) {
			if (passwordEncoder != null) {
				builder.userDetailsService(new ClientDetailsUserDetailsService(clientDetailsService()))
					.passwordEncoder(passwordEncoder());
			} else {
				builder.userDetailsService(new ClientDetailsUserDetailsService(clientDetailsService()));
			}
		} else { 
			for (AuthenticationProvider provider: authenticationProviders) {
				builder.authenticationProvider(provider);
			}
		}
		http.securityContext().securityContextRepository(new NullSecurityContextRepository()).and().csrf().disable()
				.httpBasic().authenticationEntryPoint(this.authenticationEntryPoint).realmName(realm);
		if (sslOnly) {
			http.requiresChannel().anyRequest().requiresSecure();
		}
	}

	private PasswordEncoder passwordEncoder() {
		return new PasswordEncoder() {

			@Override
			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				return StringUtils.hasText(encodedPassword) ? passwordEncoder.matches(rawPassword, encodedPassword)
						: true;
			}

			@Override
			public String encode(CharSequence rawPassword) {
				return passwordEncoder.encode(rawPassword);
			}
		};
	}

	@SuppressWarnings("unchecked")
	private void registerDefaultAuthenticationEntryPoint(HttpSecurity http) {
		ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling = http
				.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}
		if (authenticationEntryPoint==null) {
			BasicAuthenticationEntryPoint basicEntryPoint = new BasicAuthenticationEntryPoint();
			basicEntryPoint.setRealmName(realm);
			authenticationEntryPoint = basicEntryPoint;
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

	@Override
	public void configure(HttpSecurity http) throws Exception {
		
		// ensure this is initialized
		frameworkEndpointHandlerMapping();
		if (allowFormAuthenticationForClients) {
			clientCredentialsTokenEndpointFilter(http);
		}

		for (Filter filter : tokenEndpointAuthenticationFilters) {
			http.addFilterBefore(filter, BasicAuthenticationFilter.class);
		}

		http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
	}

	private ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter(HttpSecurity http) {
		ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter = new ClientCredentialsTokenEndpointFilter(
				frameworkEndpointHandlerMapping().getServletPath("/oauth/token"));
		clientCredentialsTokenEndpointFilter
				.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
		OAuth2AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
		authenticationEntryPoint.setTypeName("Form");
		authenticationEntryPoint.setRealmName(realm);
		clientCredentialsTokenEndpointFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
		clientCredentialsTokenEndpointFilter = postProcess(clientCredentialsTokenEndpointFilter);
		http.addFilterBefore(clientCredentialsTokenEndpointFilter, BasicAuthenticationFilter.class);
		return clientCredentialsTokenEndpointFilter;
	}

	private ClientDetailsService clientDetailsService() {
		return getBuilder().getSharedObject(ClientDetailsService.class);
	}

	private FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping() {
		return getBuilder().getSharedObject(FrameworkEndpointHandlerMapping.class);
	}

	/**
	 * Adds a new custom authentication filter for the TokenEndpoint. Filters will be set upstream of the default
	 * BasicAuthenticationFilter.
	 * 
	 * @param filter
	 */
	public void addTokenEndpointAuthenticationFilter(Filter filter) {
		this.tokenEndpointAuthenticationFilters.add(filter);
	}

	/**
	 * Sets a new list of custom authentication filters for the TokenEndpoint. Filters will be set upstream of the
	 * default BasicAuthenticationFilter.
	 * 
	 * @param filters The authentication filters to set.
	 */
	public void tokenEndpointAuthenticationFilters(List<Filter> filters) {
		Assert.notNull(filters, "Custom authentication filter list must not be null");
		this.tokenEndpointAuthenticationFilters = new ArrayList<Filter>(filters);
	}
}
