package org.cloudfoundry.identity.uaa.oauth;

import java.util.Map;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
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
	
	private AccessTokenConverter tokenConverter = new DefaultTokenConverter();
	private ResourceServerTokenServices resourceServerTokenServices;

	public void setTokenConverter(AccessTokenConverter tokenConverter) {
		this.tokenConverter = tokenConverter;
	}
	
	public void setTokenServices(ResourceServerTokenServices resourceServerTokenServices) {
		this.resourceServerTokenServices = resourceServerTokenServices;
	}

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(resourceServerTokenServices, "tokenServices must be set");
	}

	@RequestMapping(value = "/check_token")
	@ResponseBody
	public Map<String, Object> checkToken(@RequestParam("token") String value) {

		OAuth2AccessToken token = resourceServerTokenServices.readAccessToken(value);
		if (token == null) {
			throw new InvalidTokenException("Token was not recognised");
		}

		if (token.isExpired()) {
			throw new InvalidTokenException("Token has expired");
		}

		OAuth2Authentication authentication = resourceServerTokenServices.loadAuthentication(value);
		Map<String, Object> response = tokenConverter.convertAccessToken(token, authentication);

		return response;
	}

}
