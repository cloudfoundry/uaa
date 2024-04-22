package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ClientDetailsServiceBuilder<B extends ClientDetailsServiceBuilder<B>> extends SecurityConfigurerAdapter<ClientDetailsService, B>
		implements SecurityBuilder<ClientDetailsService> {

	private List<ClientBuilder> clientBuilders = new ArrayList<ClientBuilder>();

	public InMemoryClientDetailsServiceBuilder inMemory() throws Exception {
		return new InMemoryClientDetailsServiceBuilder();
	}

	@SuppressWarnings("rawtypes")
	public ClientDetailsServiceBuilder<?> clients(final ClientDetailsService clientDetailsService) throws Exception {
		return new ClientDetailsServiceBuilder() {
			@Override
			public ClientDetailsService build() throws Exception {
				return clientDetailsService;
			}
		};
	}

	public ClientBuilder withClient(String clientId) {
		ClientBuilder clientBuilder = new ClientBuilder(clientId);
		this.clientBuilders.add(clientBuilder);
		return clientBuilder;
	}

	@Override
	public ClientDetailsService build() throws Exception {
		for (ClientBuilder clientDetailsBldr : clientBuilders) {
			addClient(clientDetailsBldr.clientId, clientDetailsBldr.build());
		}
		return performBuild();
	}

	protected void addClient(String clientId, ClientDetails build) {
	}

	protected ClientDetailsService performBuild() {
		throw new UnsupportedOperationException("Cannot build client services (maybe use inMemory() or jdbc()).");
	}

	public final class ClientBuilder {
		private final String clientId;

		private Collection<String> authorizedGrantTypes = new LinkedHashSet<String>();

		private Collection<String> authorities = new LinkedHashSet<String>();

		private Integer accessTokenValiditySeconds;

		private Integer refreshTokenValiditySeconds;

		private Collection<String> scopes = new LinkedHashSet<String>();

		private Collection<String> autoApproveScopes = new HashSet<String>();

		private String secret;

		private Set<String> registeredRedirectUris = new HashSet<String>();

		private Set<String> resourceIds = new HashSet<String>();

		private boolean autoApprove;

		private Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();

		private ClientDetails build() {
			UaaClientDetails result = new UaaClientDetails();
			result.setClientId(clientId);
			result.setAuthorizedGrantTypes(authorizedGrantTypes);
			result.setAccessTokenValiditySeconds(accessTokenValiditySeconds);
			result.setRefreshTokenValiditySeconds(refreshTokenValiditySeconds);
			result.setRegisteredRedirectUri(registeredRedirectUris);
			result.setClientSecret(secret);
			result.setScope(scopes);
			result.setAuthorities(AuthorityUtils.createAuthorityList(authorities.toArray(new String[authorities.size()])));
			result.setResourceIds(resourceIds);
			result.setAdditionalInformation(additionalInformation);
			if (autoApprove) {
				result.setAutoApproveScopes(scopes);
			}
			else {
				result.setAutoApproveScopes(autoApproveScopes);
			}
			return result;
		}

		public ClientBuilder resourceIds(String... resourceIds) {
			for (String resourceId : resourceIds) {
				this.resourceIds.add(resourceId);
			}
			return this;
		}

		public ClientBuilder redirectUris(String... registeredRedirectUris) {
			for (String redirectUri : registeredRedirectUris) {
				this.registeredRedirectUris.add(redirectUri);
			}
			return this;
		}

		public ClientBuilder authorizedGrantTypes(String... authorizedGrantTypes) {
			for (String grant : authorizedGrantTypes) {
				this.authorizedGrantTypes.add(grant);
			}
			return this;
		}

		public ClientBuilder accessTokenValiditySeconds(int accessTokenValiditySeconds) {
			this.accessTokenValiditySeconds = accessTokenValiditySeconds;
			return this;
		}

		public ClientBuilder refreshTokenValiditySeconds(int refreshTokenValiditySeconds) {
			this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
			return this;
		}

		public ClientBuilder secret(String secret) {
			this.secret = secret;
			return this;
		}

		public ClientBuilder scopes(String... scopes) {
			for (String scope : scopes) {
				this.scopes.add(scope);
			}
			return this;
		}

		public ClientBuilder authorities(String... authorities) {
			for (String authority : authorities) {
				this.authorities.add(authority);
			}
			return this;
		}

		public ClientBuilder autoApprove(boolean autoApprove) {
			this.autoApprove = autoApprove;
			return this;
		}

		public ClientBuilder autoApprove(String... scopes) {
			for (String scope : scopes) {
				this.autoApproveScopes.add(scope);
			}
			return this;
		}

		public ClientBuilder additionalInformation(Map<String, ?> map) {
			this.additionalInformation.putAll(map);
			return this;
		}

		public ClientBuilder additionalInformation(String... pairs) {
			for (String pair : pairs) {
				String separator = ":";
				if (!pair.contains(separator) && pair.contains("=")) {
					separator = "=";
				}
				int index = pair.indexOf(separator);
				String key = pair.substring(0, index > 0 ? index : pair.length());
				String value = index > 0 ? pair.substring(index+1) : null;
				this.additionalInformation.put(key, (Object) value);
			}
			return this;
		}

		public ClientDetailsServiceBuilder<B> and() {
			return ClientDetailsServiceBuilder.this;
		}

		private ClientBuilder(String clientId) {
			this.clientId = clientId;
		}

	}

}
