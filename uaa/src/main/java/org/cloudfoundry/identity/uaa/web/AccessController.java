package org.cloudfoundry.identity.uaa.web;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.UnconfirmedAuthorizationCodeClientToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.context.request.WebRequest;

/**
 * Controller for retrieving the model for and displaying the confirmation page for access to a protected resource.
 *
 * @author Dave Syer
 */
@Controller
@SessionAttributes(types = UnconfirmedAuthorizationCodeClientToken.class)
public class AccessController {

	private ClientDetailsService clientDetailsService;

	@ModelAttribute("identity")
	public String getIdentity(HttpSession session) {
		return null;
	}

	@RequestMapping("/oauth/confirm_access")
	public String confirm(UnconfirmedAuthorizationCodeClientToken clientAuth, Map<String, Object> model, final HttpServletRequest request)
			throws Exception {

		if (clientAuth == null) {
			model.put(
					"error",
					"No client authentication token is present in the request, so we cannot confirm access (we don't know what you are asking for).");
			// response.sendError(HttpServletResponse.SC_BAD_REQUEST);
		} else {
			ClientDetails client = clientDetailsService.loadClientByClientId(clientAuth.getClientId());
			model.put("auth_request", clientAuth);
			model.put("client", client);
			model.put("message", "To confirm or deny access POST to the following locations with the parameters requested.");
			Map<String, Object> options = new HashMap<String, Object>() {
				{
					put("confirm", new HashMap<String, String>() {
						{
							put("location", getLocation(request, "oauth/authorize"));
							put("key", "user_oauth_approval");
							put("value", "true");
						}

					});
					put("deny", new HashMap<String, String>() {
						{
							put("location", getLocation(request, "oauth/authorize"));
							put("key", "user_oauth_approval");
							put("value", "false");
						}

					});
				}
			};
			model.put("options", options);
		}
		return "access_confirmation";

	}

	@RequestMapping(value="/login", method=RequestMethod.GET)
	public String defaultLoginPage(Map<String, Object> model, final WebRequest request) {

		String username = "";
		if (model.containsKey("claimed_identity")) {
			String identity = (String) model.get("claimed_identity");
			username = extractUserName(identity);
		}
		model.put("username", username);

		model.put("message",
				"You are logged out. Please use the /login_info endpoint to discover how to login.");

		return "login";

	}

	private String extractUserName(String identity) {
		if (identity==null) {
			return "";
		}
		String[] split = identity.split("/");
		return split.length==1 ? identity : split[split.length-1];
	}

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

	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	private String getLocation(HttpServletRequest request, String path) {
		return "http://" + request.getHeader("Host") + request.getContextPath() + "/" + path;
	}

}
