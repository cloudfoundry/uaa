package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller which decodes access tokens for clients who are not able to do so (or where opaque token
 * values are used).
 *
 * @author Luke Taylor
 */
@Controller
public class CheckTokenEndpoint implements InitializingBean {
	private TokenStore tokenStore;

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(tokenStore, "tokenServices must be set");
	}

	@RequestMapping (value = "/check_token")
	@ResponseBody
	public Map<String,Object> checkToken(@RequestParam ("token") String value) {
		Map<String,Object> response = new HashMap<String,Object>();
		OAuth2AccessToken token = tokenStore.readAccessToken(value);

		if (token == null) {
			response.put("error", "invalid_token");
			return response;
		}

		OAuth2Authentication authentication = tokenStore.readAuthentication(token);
		UaaPrincipal principal = (UaaPrincipal) authentication.getUserAuthentication().getPrincipal();

		response.put("user_id", principal.getId());
		response.put("user_name", principal.getName());
		response.put("user_email", principal.getEmail());
		response.put("scope", token.getScope());

		return response;
	}

	@Autowired
	public void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}
}
