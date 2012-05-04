package org.cloudfoundry.identity.uaa.login;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.security.Principal;
import java.util.Arrays;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.openid2.UaaUserDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

/**
 * Controller that manages OAuth authorization via a remote UAA service. Use this in conjunction with the authentication
 * mechanism of your choice (LDAP, Google OpenID etc.) to serve OAuth2 tokens to clients registered in the remote
 * server.
 * 
 * @author Dave Syer
 * 
 */
@Controller
@SessionAttributes(value = "cookie")
public class RemoteUaaController {

	private static final Log logger = LogFactory.getLog(RemoteUaaController.class);

	private static final String CONTENT_LENGTH = "Content-Length";

	private static final String TRANSFER_ENCODING = "Transfer-Encoding";

	private static final String HOST = "Host";

	private static String DEFAULT_BASE_UAA_URL = "https://uaa.cloudfoundry.com";

	private RestTemplate defaultTemplate = new RestTemplate();

	private RestOperations authorizationTemplate = new RestTemplate();

	private String baseUrl;

	private String uaaHost;

	/**
	 * @param authorizationTemplate the authorizationTemplate to set
	 */
	public void setAuthorizationTemplate(RestOperations authorizationTemplate) {
		this.authorizationTemplate = authorizationTemplate;
	}

	public RemoteUaaController() {
		// The default java.net client doesn't allow you to handle 4xx responses
		defaultTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
		defaultTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
			public boolean hasError(ClientHttpResponse response) throws IOException {
				HttpStatus statusCode = response.getStatusCode();
				return statusCode.series() == HttpStatus.Series.SERVER_ERROR;
			}
		});
		setUaaBaseUrl(DEFAULT_BASE_UAA_URL);
	}

	/**
	 * @param baseUrl the base uaa url
	 */
	public void setUaaBaseUrl(String baseUrl) {
		this.baseUrl = baseUrl;
		try {
			this.uaaHost = new URI(baseUrl).getHost();
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException("Could not extract host from URI: " + baseUrl);
		}
	}

	@RequestMapping(value = { "/login", "/login_info" }, method = RequestMethod.GET)
	public String prompts(HttpServletRequest request, @RequestHeader HttpHeaders headers, Model model,
			Principal principal) throws Exception {
		String path = extractPath(request);
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = defaultTemplate.exchange(baseUrl + "/" + path, HttpMethod.GET,
				new HttpEntity<Void>(null, getRequestHeaders(headers)), Map.class);
		@SuppressWarnings("unchecked")
		Map<String, Object> body = (Map<String, Object>) response.getBody();
		model.addAllAttributes(body);
		if (principal == null) {
			return "login";
		}
		return "home";
	}

	@RequestMapping(value = "/oauth/authorize", params = "response_type")
	public ModelAndView startAuthorization(HttpServletRequest request, @RequestParam Map<String, String> parameters,
			Map<String, Object> model, @RequestHeader HttpHeaders headers, Principal principal) throws Exception {

		String path = extractPath(request);

		MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
		map.setAll(parameters);
		if (principal != null) {
			map.set("login", getLoginCredentials(principal));
		}

		HttpHeaders requestHeaders = new HttpHeaders();
		requestHeaders.putAll(getRequestHeaders(headers));
		requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		requestHeaders.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		requestHeaders.remove("Cookie");

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = authorizationTemplate.exchange(baseUrl + "/" + path, HttpMethod.POST,
				new HttpEntity<MultiValueMap<String, String>>(map, requestHeaders), Map.class);

		saveCookie(response.getHeaders(), model);

		@SuppressWarnings("unchecked")
		Map<String, Object> body = (Map<String, Object>) response.getBody();
		if (body != null) {
			// User approval is required
			logger.debug("Response: " + body);
			model.putAll(body);
			return new ModelAndView("access_confirmation", model);
		}

		String location = response.getHeaders().getFirst("Location");
		if (location != null) {
			return new ModelAndView(new RedirectView(location));
		}

		throw new IllegalStateException("Neither a redirect nor a user approval");

	}

	@RequestMapping(value = "/oauth/authorize", method = RequestMethod.POST, params = "user_oauth_approval")
	@ResponseBody
	public ResponseEntity<byte[]> approveOrDeny(HttpServletRequest request, HttpEntity<byte[]> entity,
			Map<String, Object> model, SessionStatus sessionStatus) throws Exception {
		sessionStatus.setComplete();
		return passthru(request, entity, model);
	}

	@RequestMapping(value = "/oauth/**", method = RequestMethod.POST)
	@ResponseBody
	public ResponseEntity<byte[]> post(HttpServletRequest request, HttpEntity<byte[]> entity,
			Map<String, Object> model, SessionStatus sessionStatus) throws Exception {
		return passthru(request, entity, model);
	}

	private void saveCookie(HttpHeaders headers, Map<String, Object> model) {
		// Save back end cookie for later
		String cookie = headers.getFirst("Set-Cookie");
		if (cookie != null) {
			logger.debug("Saved back end cookie: " + cookie);
			model.put("cookie", cookie);
		}
	}

	private String getLoginCredentials(Principal principal) {
		StringBuilder login = new StringBuilder("{");
		appendField(login, "username", principal.getName());
		if (principal instanceof Authentication) {
			Object details = ((Authentication) principal).getPrincipal();
			if (details instanceof UaaUserDetails) {
				UaaUser user = ((UaaUserDetails) details).getUser();
				appendField(login, "family_name", user.getFamilyName());
				appendField(login, "given_name", user.getGivenName());
				appendField(login, "email", user.getEmail());
			}
		}
		login.append("}");
		return login.toString();
	}

	private void appendField(StringBuilder login, String key, Object value) {
		if (value != null) {
			if (login.length() > 1) {
				login.append(",");
			}
			quote(login, key).append(":");
			if (value instanceof CharSequence) {
				quote(login, (CharSequence) value);
			}
			else {
				login.append(value);
			}
		}
	}

	private StringBuilder quote(StringBuilder login, CharSequence string) {
		login.append("\"").append(string).append("\"");
		return login;
	}

	private ResponseEntity<byte[]> passthru(HttpServletRequest request, HttpEntity<byte[]> entity,
			Map<String, Object> model) throws Exception {

		String path = extractPath(request);

		HttpHeaders requestHeaders = new HttpHeaders();
		requestHeaders.putAll(getRequestHeaders(entity.getHeaders()));
		// Get back end cookie if saved in session
		String cookie = (String) model.get("cookie");
		if (cookie != null) {
			logger.debug("Found back end cookie: " + cookie);
			requestHeaders.set("Cookie", cookie);
		}

		ResponseEntity<byte[]> response = defaultTemplate.exchange(baseUrl + "/" + path, HttpMethod.POST,
				new HttpEntity<byte[]>(entity.getBody(), requestHeaders), byte[].class);
		HttpHeaders outgoingHeaders = getResponseHeaders(response.getHeaders());
		return new ResponseEntity<byte[]>(response.getBody(), outgoingHeaders, response.getStatusCode());

	}

	private HttpHeaders getResponseHeaders(HttpHeaders headers) {
		// Some of the headers coming back are poisonous apparently (content-length?)...
		HttpHeaders outgoingHeaders = new HttpHeaders();
		outgoingHeaders.putAll(headers);
		if (headers.getContentLength() >= 0) {
			outgoingHeaders.remove(CONTENT_LENGTH);
		}
		if (headers.containsKey(TRANSFER_ENCODING)) {
			outgoingHeaders.remove(TRANSFER_ENCODING);
		}
		return outgoingHeaders;
	}

	private HttpHeaders getRequestHeaders(HttpHeaders headers) {
		// Some of the headers coming back are poisonous apparently (content-length?)...
		HttpHeaders outgoingHeaders = new HttpHeaders();
		outgoingHeaders.putAll(headers);
		outgoingHeaders.remove(HOST);
		outgoingHeaders.set(HOST, uaaHost);
		logger.debug("Outgoing headers: " + outgoingHeaders);
		return outgoingHeaders;
	}

	private String extractPath(HttpServletRequest request) {
		String query = request.getQueryString();
		try {
			query = query == null ? "" : "?" + URLDecoder.decode(query, "UTF-8");
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Cannot decode query string: " + query);
		}
		String path = request.getRequestURI() + query;
		String context = request.getContextPath();
		path = path.substring(context.length());
		if (path.startsWith("/")) {
			// In the root context we have to remove this as well
			path = path.substring(1);
		}
		logger.debug("Path: " + path);
		return path;
	}

}
