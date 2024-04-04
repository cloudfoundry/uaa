package org.cloudfoundry.identity.uaa.oauth.provider.expression;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Set;

public abstract class OAuth2ExpressionUtils {

	public static boolean clientHasAnyRole(Authentication authentication, String... roles) {
		if (authentication instanceof OAuth2Authentication) {
			OAuth2Request clientAuthentication = ((OAuth2Authentication) authentication).getOAuth2Request();
			Collection<? extends GrantedAuthority> clientAuthorities = clientAuthentication.getAuthorities();
			if (clientAuthorities != null) {
				Set<String> roleSet = AuthorityUtils.authorityListToSet(clientAuthorities);
				for (String role : roles) {
					if (roleSet.contains(role)) {
						return true;
					}
				}
			}
		}
	
		return false;
	}

	public static boolean isOAuth(Authentication authentication) {
		
		if (authentication instanceof OAuth2Authentication) {
			return true;
		}
	
		return false;
	}

	public static boolean isOAuthClientAuth(Authentication authentication) {
		
		if (authentication instanceof OAuth2Authentication) {
			return authentication.isAuthenticated() && ((OAuth2Authentication)authentication).isClientOnly();
		}
	
		return false;
	}

	public static boolean isOAuthUserAuth(Authentication authentication) {
		
		if (authentication instanceof OAuth2Authentication) {
			return authentication.isAuthenticated() && !((OAuth2Authentication)authentication).isClientOnly();
		}
	
		return false;
	}

	public static boolean hasAnyScope(Authentication authentication, String[] scopes) {

		if (authentication instanceof OAuth2Authentication) {
			OAuth2Request clientAuthentication = ((OAuth2Authentication) authentication).getOAuth2Request();
			Collection<String> assigned = clientAuthentication.getScope();
			if (assigned != null) {
				for (String scope : scopes) {
					if (assigned.contains(scope)) {
						return true;
					}
				}
			}
		}
	
		return false;
	}

	public static boolean hasAnyScopeMatching(Authentication authentication, String[] scopesRegex) {

		if (authentication instanceof OAuth2Authentication) {
			OAuth2Request clientAuthentication = ((OAuth2Authentication) authentication).getOAuth2Request();
			for (String scope : clientAuthentication.getScope()) {
				for (String regex : scopesRegex) {
					if (scope.matches(regex)) {
						return true;
					}
				}
			}
		}

		return false;
	}

}
