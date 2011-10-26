package org.cloudfoundry.identity.uaa.web;

import java.security.Principal;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaUser;
import org.cloudfoundry.identity.uaa.authentication.UaaUserService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller which decodes access tokens for resource owners who are not able to do so (or where opaque token
 * values are used).
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
@Controller
public class CheckTokenEndpoint implements InitializingBean {
	private final Log logger = LogFactory.getLog(getClass());

	private TokenStore tokenStore;
	private UaaUserService userService;

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(tokenStore, "tokenServices must be set");
		Assert.notNull(userService, "userService must be set");
	}

	@RequestMapping (value = "/check_token")
	@ResponseBody
	public Map<String,Object> checkToken(@RequestParam ("token") String value, Principal resourceOwner) {
		logger.debug("check_token called by " + resourceOwner);
		Map<String,Object> response = new HashMap<String,Object>();
		OAuth2AccessToken token = tokenStore.readAccessToken(value);

		if (token == null) {
			response.put("error", "invalid_token");
			return response;
		}
		// TODO: Check token scope matches the identity of the caller principal
		OAuth2Authentication authentication = tokenStore.readAuthentication(token);
		User principal = (User) authentication.getUserAuthentication().getPrincipal();

		UaaUser user = userService.getUser(principal.getUsername());

		response.put("user_id", userService.getPrincipal(user).getId());
		response.put("user_name", user.getUsername());
		response.put("user_email", user.getEmail());
		response.put("scope", token.getScope());
		response.put("user_authorities", getAuthorities(authentication.getAuthorities()));

		return response;
	}

	private Collection<String> getAuthorities(Collection<GrantedAuthority> authorities) {
		HashSet<String> result = new HashSet<String>();
		for (GrantedAuthority authority : authorities) {
			result.add(authority.getAuthority());
		}
		return result;
	}

	@Autowired
	public void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	@Autowired
	public void setUserService(UaaUserService userService) {
		this.userService = userService;
	}
}
