package org.cloudfoundry.identity.uaa.oauth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.openid.UserInfo;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller which decodes access tokens for clients who are not able to do so (or where opaque token values are used).
 * 
 * @author Luke Taylor
 */
@Controller
public class CheckTokenEndpoint implements InitializingBean {
	private TokenStore tokenStore;

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(tokenStore, "tokenStore must be set");
	}

	@RequestMapping(value = "/check_token")
	@ResponseBody
	public Map<String, Object> checkToken(@RequestParam("token") String value) {
		Map<String, Object> response = new HashMap<String, Object>();
		OAuth2AccessToken token = tokenStore.readAccessToken(value);

		if (token == null) {
			throw new InvalidTokenException("Token was not recognised");
		}

		if (token.isExpired()) {
			throw new InvalidTokenException("Token has expired");
		}

		OAuth2Authentication authentication = tokenStore.readAuthentication(token);
		AuthorizationRequest clientToken = authentication.getAuthorizationRequest();

		if (!authentication.isClientOnly()
				&& authentication.getUserAuthentication().getPrincipal() instanceof UaaPrincipal) {

			UaaPrincipal principal = (UaaPrincipal) authentication.getUserAuthentication().getPrincipal();

			response.put("id", principal.getId());
			response.put(UserInfo.USER_ID, principal.getName());
			response.put(UserInfo.EMAIL, principal.getEmail());
			Collection<? extends GrantedAuthority> authorities = authentication.getUserAuthentication()
					.getAuthorities();
			if (authorities != null) {
				response.put("user_authorities", getAuthorities(authorities));
			}

		}
		response.put(OAuth2AccessToken.SCOPE, token.getScope());
		if (token.getExpiresIn() > 0) {
			response.put(OAuth2AccessToken.EXPIRES_IN, token.getExpiresIn());
		}

		response.put("client_id", clientToken.getClientId());
		if (clientToken.getAuthorities() != null) {
			response.put("client_authorities", getAuthorities(clientToken.getAuthorities()));
		}
		if (clientToken.getResourceIds() != null && !clientToken.getResourceIds().isEmpty()) {
			response.put("resource_ids", clientToken.getResourceIds());
		}

		return response;
	}

	private Collection<String> getAuthorities(Collection<? extends GrantedAuthority> authorities) {
		Collection<String> result = new ArrayList<String>();
		for (GrantedAuthority authority : authorities) {
			result.add(authority.getAuthority());
		}
		return result;
	}

	@Autowired
	public void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}
}
