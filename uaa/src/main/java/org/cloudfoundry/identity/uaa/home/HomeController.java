package org.cloudfoundry.identity.uaa.home;

import java.security.Principal;
import java.util.Map;

import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.context.request.WebRequest;

/**
 * Controller for retrieving the model for demo home page.
 *
 * @author Dave Syer
 */
@Controller
@SessionAttributes(types = AuthorizationRequest.class)
public class HomeController {

	@RequestMapping(value = { "/", "/home" })
	public String homePage(Map<String, Object> model, WebRequest request, Principal principal) {

		Object error = request.getAttribute("SPRING_SECURITY_403_EXCEPTION", WebRequest.SCOPE_REQUEST);
		if (error != null) {
			model.put("error", "You don't have access to this resource (" + error + ")");
		}
		model.put("message", "You are logged in.  Log out by sending a GET to the location provided.");
		model.put("location", "http:" + request.getHeader("Host") + request.getContextPath() + "/logout.do");
		model.put("principal", principal);
		return "home";

	}

}
