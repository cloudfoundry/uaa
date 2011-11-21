package org.cloudfoundry.identity.uaa.web;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientToken;
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
		Assert.notNull(tokenStore, "tokenServices must be set");
	}

	@RequestMapping(value = "/check_token")
	@ResponseBody
	public Map<String, Object> checkToken(@RequestParam("token") String value) {
		Map<String, Object> response = new HashMap<String, Object>();
		OAuth2AccessToken token = tokenStore.readAccessToken(value);

		if (token == null) {
			response.put("error", "invalid_token");
			return response;
		}

		if (token.isExpired()) {
			response.put("error", "expired_token");
			return response;
		}

		OAuth2Authentication authentication = tokenStore.readAuthentication(token);
		UaaPrincipal principal = (UaaPrincipal) authentication.getUserAuthentication().getPrincipal();
		ClientToken clientToken = authentication.getClientAuthentication();

		response.put("user_id", principal.getId());
		response.put("user_name", principal.getName());
		response.put("user_email", principal.getEmail());
		Collection<? extends GrantedAuthority> authorities = authentication.getUserAuthentication().getAuthorities();
		if (authorities != null) {
			response.put("user_authorities", getAuthorities(authorities));
		}
		response.put("scope", token.getScope());

		response.put("client_id", clientToken.getClientId());
		if (clientToken.getClientSecret() != null) {
			response.put("client_secret", clientToken.getClientSecret());
		}
		if (clientToken.getAuthorities() != null) {
			response.put("client_authorities", getAuthorities(clientToken.getAuthorities()));
		}
		response.put("resource_ids", clientToken.getResourceIds());

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
