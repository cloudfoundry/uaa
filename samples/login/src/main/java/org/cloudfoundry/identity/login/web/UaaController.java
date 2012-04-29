package org.cloudfoundry.identity.login.web;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

@Controller
public class UaaController {

	private static final String SET_COOKIE = "Content-Length";

	private static String DEFAULT_BASE_UAA_URL = "http://uaa.cloudfoundry.com";

	private RestTemplate restTemplate = new RestTemplate();

	private String uaaUrlPattern;

	public UaaController() {
		restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
			public void handleError(ClientHttpResponse response) throws IOException {
			}
		});
		setBaseUaaUrl(DEFAULT_BASE_UAA_URL);
	}

	/**
	 * @param baseUrl the base uaa url
	 */
	public void setBaseUaaUrl(String baseUrl) {
		uaaUrlPattern = baseUrl;
	}

	@RequestMapping(value = { "/login", "/oauth/**" }, method = RequestMethod.GET)
	@ResponseBody
	public ResponseEntity<String> get(HttpServletRequest request, @RequestHeader HttpHeaders headers) throws Exception {

		String path = extractPath(request);

		ResponseEntity<String> response = restTemplate.exchange(uaaUrlPattern + "/" + path, HttpMethod.GET,
				new HttpEntity<Void>(null, headers), String.class);
		// Some of the headers coming back from VCAP are poisonous apparently (content-length?)...
		HttpHeaders outgoingHeaders = getResponseHeaders(response.getHeaders());
		return new ResponseEntity<String>(response.getBody(), outgoingHeaders, response.getStatusCode());

	}

	@RequestMapping(value = "/oauth/**", method = RequestMethod.POST)
	@ResponseBody
	public ResponseEntity<byte[]> post(HttpServletRequest request, HttpEntity<byte[]> entity) throws Exception {

		String path = extractPath(request);
		ResponseEntity<byte[]> response = restTemplate.exchange(uaaUrlPattern + "/" + path, HttpMethod.POST, entity,
				byte[].class);
		HttpHeaders outgoingHeaders = getResponseHeaders(response.getHeaders());
		return new ResponseEntity<byte[]>(response.getBody(), outgoingHeaders, response.getStatusCode());

	}

	private HttpHeaders getResponseHeaders(HttpHeaders headers) {
		// Some of the headers coming back from VCAP are poisonous apparently (content-length?)...
		HttpHeaders outgoingHeaders = new HttpHeaders();
		outgoingHeaders.putAll(headers);
		if (headers.getContentLength() >= 0) {
			outgoingHeaders.remove(SET_COOKIE);
		}
		return outgoingHeaders;
	}

	private String extractPath(HttpServletRequest request) {
		String path = request.getRequestURI()
				+ (request.getQueryString() == null ? "" : ("?" + request.getQueryString()));
		String context = request.getContextPath();
		path = path.substring(context.length());
		if (path.startsWith("/")) {
			// In the root context we have to remove this as well
			path = path.substring(1);
		}
		return path;
	}

}
