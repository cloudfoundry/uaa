package org.springframework.security.oauth2.config.annotation.web.configurers;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.beans.org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.CompositeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.approval.UserApprovalHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.client.ClientCredentialsTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.password.ResourceOwnerPasswordTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.refresh.RefreshTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.request.DefaultOAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.request.DefaultOAuth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.ConsumerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.DefaultTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.InMemoryTokenStore;
import org.cloudfoundry.identity.uaa.oauth.provider.token.ResourceServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.TokenEnhancer;
import org.cloudfoundry.identity.uaa.oauth.provider.token.TokenStore;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.ProxyCreator;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.context.request.WebRequestInterceptor;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class AuthorizationServerEndpointsConfigurer {

	private AuthorizationServerTokenServices tokenServices;

	private ConsumerTokenServices consumerTokenServices;

	private AuthorizationCodeServices authorizationCodeServices;

	private ResourceServerTokenServices resourceTokenServices;

	private TokenStore tokenStore;

	private TokenEnhancer tokenEnhancer;

	private AccessTokenConverter accessTokenConverter;

	private ApprovalStore approvalStore;

	private TokenGranter tokenGranter;

	private OAuth2RequestFactory requestFactory;

	private OAuth2RequestValidator requestValidator;

	private UserApprovalHandler userApprovalHandler;

	private AuthenticationManager authenticationManager;

	private ClientDetailsService clientDetailsService;

	private String prefix;

	private Map<String, String> patternMap = new HashMap<String, String>();

	private Set<HttpMethod> allowedTokenEndpointRequestMethods = new HashSet<HttpMethod>();

	private FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping;

	private boolean approvalStoreDisabled;

	private List<Object> interceptors = new ArrayList<Object>();

	private DefaultTokenServices defaultTokenServices;

	private UserDetailsService userDetailsService;

	private boolean tokenServicesOverride = false;

	private boolean userDetailsServiceOverride = false;

	private boolean reuseRefreshToken = true;

	private WebResponseExceptionTranslator<OAuth2Exception> exceptionTranslator;

	private RedirectResolver redirectResolver;

	public AuthorizationServerTokenServices getTokenServices() {
		return ProxyCreator.getProxy(AuthorizationServerTokenServices.class,
				new ObjectFactory<AuthorizationServerTokenServices>() {
					@Override
					public AuthorizationServerTokenServices getObject() throws BeansException {
						return tokenServices();
					}
				});
	}

	public TokenStore getTokenStore() {
		return tokenStore();
	}

	public TokenEnhancer getTokenEnhancer() {
		return tokenEnhancer;
	}

	public AccessTokenConverter getAccessTokenConverter() {
		return accessTokenConverter();
	}

	public ApprovalStore getApprovalStore() {
		return approvalStore;
	}

	public ClientDetailsService getClientDetailsService() {
		return ProxyCreator.getProxy(ClientDetailsService.class, new ObjectFactory<ClientDetailsService>() {
			@Override
			public ClientDetailsService getObject() throws BeansException {
				return clientDetailsService();
			}
		});
	}

	public OAuth2RequestFactory getOAuth2RequestFactory() {
		return ProxyCreator.getProxy(OAuth2RequestFactory.class, new ObjectFactory<OAuth2RequestFactory>() {
			@Override
			public OAuth2RequestFactory getObject() throws BeansException {
				return requestFactory();
			}
		});
	}

	public OAuth2RequestValidator getOAuth2RequestValidator() {
		return requestValidator();
	}

	public UserApprovalHandler getUserApprovalHandler() {
		return userApprovalHandler();
	}

	public AuthorizationServerEndpointsConfigurer tokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer tokenEnhancer(TokenEnhancer tokenEnhancer) {
		this.tokenEnhancer = tokenEnhancer;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer reuseRefreshTokens(boolean reuseRefreshToken) {
		this.reuseRefreshToken = reuseRefreshToken;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer accessTokenConverter(AccessTokenConverter accessTokenConverter) {
		this.accessTokenConverter = accessTokenConverter;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer tokenServices(AuthorizationServerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
		if (tokenServices != null) {
			this.tokenServicesOverride = true;
		}
		return this;
	}

	public AuthorizationServerEndpointsConfigurer redirectResolver(RedirectResolver redirectResolver) {
		this.redirectResolver = redirectResolver;
		return this;
	}

	public boolean isTokenServicesOverride() {
		return tokenServicesOverride;
	}

	public boolean isUserDetailsServiceOverride() {
		return userDetailsServiceOverride;
	}

	public AuthorizationServerEndpointsConfigurer userApprovalHandler(UserApprovalHandler approvalHandler) {
		this.userApprovalHandler = approvalHandler;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer approvalStore(ApprovalStore approvalStore) {
		if (approvalStoreDisabled) {
			throw new IllegalStateException("ApprovalStore was disabled");
		}
		this.approvalStore = approvalStore;
		return this;
	}

	/**
	 * Explicitly disable the approval store, even if one would normally be added automatically (usually when JWT is not
	 * used). Without an approval store the user can only be asked to approve or deny a grant without any more granular
	 * decisions.
	 * 
	 * @return this for fluent builder
	 */
	public AuthorizationServerEndpointsConfigurer approvalStoreDisabled() {
		this.approvalStoreDisabled = true;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer prefix(String prefix) {
		this.prefix = prefix;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer pathMapping(String defaultPath, String customPath) {
		this.patternMap.put(defaultPath, customPath);
		return this;
	}

	public AuthorizationServerEndpointsConfigurer addInterceptor(HandlerInterceptor interceptor) {
		this.interceptors.add(interceptor);
		return this;
	}

	public AuthorizationServerEndpointsConfigurer addInterceptor(WebRequestInterceptor interceptor) {
		this.interceptors.add(interceptor);
		return this;
	}

	public AuthorizationServerEndpointsConfigurer exceptionTranslator(WebResponseExceptionTranslator<OAuth2Exception> exceptionTranslator) {
		this.exceptionTranslator = exceptionTranslator;
		return this;
	}

	/**
	 * The AuthenticationManager for the password grant.
	 * 
	 * @param authenticationManager an AuthenticationManager, fully initialized
	 * @return this for a fluent style
	 */
	public AuthorizationServerEndpointsConfigurer authenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer tokenGranter(TokenGranter tokenGranter) {
		this.tokenGranter = tokenGranter;
		return this;
	}

	/**
	 * N.B. this method is not part of the public API. To set up a custom ClientDetailsService please use
	 * {@link AuthorizationServerConfigurerAdapter#configure(ClientDetailsServiceConfigurer)}.
	 */
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public AuthorizationServerEndpointsConfigurer requestFactory(OAuth2RequestFactory requestFactory) {
		this.requestFactory = requestFactory;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer requestValidator(OAuth2RequestValidator requestValidator) {
		this.requestValidator = requestValidator;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer authorizationCodeServices(
			AuthorizationCodeServices authorizationCodeServices) {
		this.authorizationCodeServices = authorizationCodeServices;
		return this;
	}

	public AuthorizationServerEndpointsConfigurer allowedTokenEndpointRequestMethods(HttpMethod... requestMethods) {
		Collections.addAll(allowedTokenEndpointRequestMethods, requestMethods);
		return this;
	}

	public AuthorizationServerEndpointsConfigurer userDetailsService(UserDetailsService userDetailsService) {
		if (userDetailsService != null) {
			this.userDetailsService = userDetailsService;
			this.userDetailsServiceOverride = true;
		}
		return this;
	}

	public ConsumerTokenServices getConsumerTokenServices() {
		return consumerTokenServices();
	}

	public ResourceServerTokenServices getResourceServerTokenServices() {
		return resourceTokenServices();
	}

	public AuthorizationCodeServices getAuthorizationCodeServices() {
		return authorizationCodeServices();
	}

	public Set<HttpMethod> getAllowedTokenEndpointRequestMethods() {
		return allowedTokenEndpointRequestMethods();
	}

	public OAuth2RequestValidator getRequestValidator() {
		return requestValidator();
	}

	public TokenGranter getTokenGranter() {
		return tokenGranter();
	}

	public FrameworkEndpointHandlerMapping getFrameworkEndpointHandlerMapping() {
		return frameworkEndpointHandlerMapping();
	}

	public WebResponseExceptionTranslator<OAuth2Exception> getExceptionTranslator() {
		return exceptionTranslator();
	}

	public RedirectResolver getRedirectResolver() {
		return redirectResolver();
	}

	private ResourceServerTokenServices resourceTokenServices() {
		if (resourceTokenServices == null) {
			if (tokenServices instanceof ResourceServerTokenServices) {
				return (ResourceServerTokenServices) tokenServices;
			}
			resourceTokenServices = createDefaultTokenServices();
		}
		return resourceTokenServices;
	}

	private Set<HttpMethod> allowedTokenEndpointRequestMethods() {
		// HTTP POST should be the only allowed endpoint request method by default.
		if (allowedTokenEndpointRequestMethods.isEmpty()) {
			allowedTokenEndpointRequestMethods.add(HttpMethod.POST);
		}
		return allowedTokenEndpointRequestMethods;
	}

	private ConsumerTokenServices consumerTokenServices() {
		if (consumerTokenServices == null) {
			if (tokenServices instanceof ConsumerTokenServices) {
				return (ConsumerTokenServices) tokenServices;
			}
			consumerTokenServices = createDefaultTokenServices();
		}
		return consumerTokenServices;
	}

	private AuthorizationServerTokenServices tokenServices() {
		if (tokenServices != null) {
			return tokenServices;
		}
		this.tokenServices = createDefaultTokenServices();
		return tokenServices;
	}

	public AuthorizationServerTokenServices getDefaultAuthorizationServerTokenServices() {
		if (defaultTokenServices != null) {
			return defaultTokenServices;
		}
		this.defaultTokenServices = createDefaultTokenServices();
		return this.defaultTokenServices;
	}

	private DefaultTokenServices createDefaultTokenServices() {
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setTokenStore(tokenStore());
		tokenServices.setSupportRefreshToken(true);
		tokenServices.setReuseRefreshToken(reuseRefreshToken);
		tokenServices.setClientDetailsService(clientDetailsService());
		tokenServices.setTokenEnhancer(tokenEnhancer());
		addUserDetailsService(tokenServices, this.userDetailsService);
		return tokenServices;
	}

	private TokenEnhancer tokenEnhancer() {
		if (this.tokenEnhancer == null && accessTokenConverter() instanceof JwtAccessTokenConverter) {
			tokenEnhancer = (TokenEnhancer) accessTokenConverter;
		}
		return this.tokenEnhancer;
	}

	private AccessTokenConverter accessTokenConverter() {
		if (this.accessTokenConverter == null) {
			accessTokenConverter = new DefaultAccessTokenConverter();
		}
		return this.accessTokenConverter;
	}

	private TokenStore tokenStore() {
		if (tokenStore == null) {
			this.tokenStore = new InMemoryTokenStore();
		}
		return this.tokenStore;
	}

	private ApprovalStore approvalStore() {
		if (approvalStore == null && tokenStore() != null && !isApprovalStoreDisabled()) {
			ApprovalStore tokenStoreApproval = new ApprovalStore() {
				@Override
				public boolean addApproval(Approval approval, String zoneId) {
					return false;
				}

				@Override
				public boolean revokeApproval(Approval approval, String zoneId) {
					return false;
				}

				@Override
				public boolean revokeApprovalsForUser(String userId, String zoneId) {
					return false;
				}

				@Override
				public boolean revokeApprovalsForClient(String clientId, String zoneId) {
					return false;
				}

				@Override
				public boolean revokeApprovalsForClientAndUser(String clientId, String userId, String zoneId) {
					return false;
				}

				@Override
				public List<Approval> getApprovals(String userId, String clientId, String zoneId) {
					return null;
				}

				@Override
				public List<Approval> getApprovalsForUser(String userId, String zoneId) {
					return null;
				}

				@Override
				public List<Approval> getApprovalsForClient(String clientId, String zoneId) {
					return null;
				}
			};
			this.approvalStore = tokenStoreApproval;
		}
		return this.approvalStore;
	}

	private boolean isApprovalStoreDisabled() {
		return approvalStoreDisabled;
	}

	private ClientDetailsService clientDetailsService() {
		if (clientDetailsService == null) {
			this.clientDetailsService = new InMemoryClientDetailsService();
		}
		if (this.defaultTokenServices != null) {
			addUserDetailsService(defaultTokenServices, userDetailsService);
		}
		return this.clientDetailsService;
	}

	private void addUserDetailsService(DefaultTokenServices tokenServices, UserDetailsService userDetailsService) {
		if (userDetailsService != null) {
			PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
			provider.setPreAuthenticatedUserDetailsService(new UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken>(
					userDetailsService));
			tokenServices
					.setAuthenticationManager(new ProviderManager(Arrays.<AuthenticationProvider> asList(provider)));
		}
	}

	private UserApprovalHandler userApprovalHandler() {
		if (userApprovalHandler == null) {
			if (approvalStore() != null) {
				userApprovalHandler = new UserApprovalHandler() {

					@Override
					public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
						return false;
					}

					@Override
					public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
						return null;
					}

					@Override
					public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
						return null;
					}

					@Override
					public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
						return null;
					}
				};
			} else {
				throw new IllegalStateException("Either a TokenStore or an ApprovalStore must be provided");
			}
		}
		return this.userApprovalHandler;
	}

	private AuthorizationCodeServices authorizationCodeServices() {
		return authorizationCodeServices;
	}

	private WebResponseExceptionTranslator<OAuth2Exception> exceptionTranslator() {
		if (exceptionTranslator != null) {
			return exceptionTranslator;
		}
		exceptionTranslator = new DefaultWebResponseExceptionTranslator();
		return exceptionTranslator;
	}

	private RedirectResolver redirectResolver() {
		if (redirectResolver != null) {
			return redirectResolver;
		}
		redirectResolver = new DefaultRedirectResolver();
		return redirectResolver;
	}

	private OAuth2RequestFactory requestFactory() {
		if (requestFactory != null) {
			return requestFactory;
		}
		requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService());
		return requestFactory;
	}

	private OAuth2RequestValidator requestValidator() {
		if (requestValidator != null) {
			return requestValidator;
		}
		requestValidator = new DefaultOAuth2RequestValidator();
		return requestValidator;
	}

	private List<TokenGranter> getDefaultTokenGranters() {
		ClientDetailsService clientDetails = clientDetailsService();
		AuthorizationServerTokenServices tokenServices = tokenServices();
		AuthorizationCodeServices authorizationCodeServices = authorizationCodeServices();
		OAuth2RequestFactory requestFactory = requestFactory();

		List<TokenGranter> tokenGranters = new ArrayList<TokenGranter>();
		tokenGranters.add(new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices, clientDetails,
				requestFactory));
		tokenGranters.add(new RefreshTokenGranter(tokenServices, clientDetails, requestFactory));
		ImplicitTokenGranter implicit = new ImplicitTokenGranter(tokenServices, clientDetails, requestFactory);
		tokenGranters.add(implicit);
		tokenGranters.add(new ClientCredentialsTokenGranter(tokenServices, clientDetails, requestFactory));
		if (authenticationManager != null) {
			tokenGranters.add(new ResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices,
					clientDetails, requestFactory));
		}
		return tokenGranters;
	}

	private TokenGranter tokenGranter() {
		if (tokenGranter == null) {
			tokenGranter = new TokenGranter() {
				private CompositeTokenGranter delegate;

				@Override
				public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
					if (delegate == null) {
						delegate = new CompositeTokenGranter(getDefaultTokenGranters());
					}
					return delegate.grant(grantType, tokenRequest);
				}
			};
		}
		return tokenGranter;
	}

	private FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping() {
		if (frameworkEndpointHandlerMapping == null) {
			frameworkEndpointHandlerMapping = new FrameworkEndpointHandlerMapping();
			frameworkEndpointHandlerMapping.setMappings(patternMap);
			frameworkEndpointHandlerMapping.setPrefix(prefix);
			frameworkEndpointHandlerMapping.setInterceptors(interceptors.toArray());
		}
		return frameworkEndpointHandlerMapping;
	}

}
