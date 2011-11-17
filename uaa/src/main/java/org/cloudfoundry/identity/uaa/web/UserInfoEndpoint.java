package org.cloudfoundry.identity.uaa.web;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller that sends user info to clients wishing to authenticate.
 *
 * @author Dave Syer
 */
@Controller
public class UserInfoEndpoint {
	
	@RequestMapping (value = "/userinfo")
	@ResponseBody
	public Map<String,String> loginInfo(Principal principal) {

		Map<String, String> response = new LinkedHashMap<String, String>();
		
		OAuth2Authentication authentication = (OAuth2Authentication) principal;
		UaaPrincipal user = (UaaPrincipal) authentication.getUserAuthentication().getPrincipal();

		response.put("user_id", user.getId());
		response.put("name", user.getName());
		response.put("email", user.getEmail());

		return response;

	}

}
