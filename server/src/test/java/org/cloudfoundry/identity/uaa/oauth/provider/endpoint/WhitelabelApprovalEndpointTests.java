package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class WhitelabelApprovalEndpointTests {
	
	private WhitelabelApprovalEndpoint endpoint = new WhitelabelApprovalEndpoint();
	private Map<String, String> parameters = new HashMap<String, String>();
	private MockHttpServletRequest request = new MockHttpServletRequest();
	private MockHttpServletResponse response = new MockHttpServletResponse();

	private AuthorizationRequest createFromParameters(Map<String, String> authorizationParameters) {
		AuthorizationRequest request = new AuthorizationRequest();
		request.setClientId(authorizationParameters.get("client_id"));
		request.setRedirectUri(authorizationParameters.get("redirect_uri"));
		request.setState(authorizationParameters.get("state"));
		request.setRequestParameters(authorizationParameters);
		return request;
	}
	
	@Test
	public void testApprovalPage() throws Exception {
		request.setContextPath("/foo");
		parameters.put("client_id", "client");
		HashMap<String, Object> model = new HashMap<String, Object>();
		model.put("authorizationRequest", createFromParameters(parameters));
		ModelAndView result = endpoint.getAccessConfirmation(model, request);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.contains("<form"));
		assertTrue("Wrong content: " + content, content.contains("/foo/oauth/authorize"));
		assertTrue("Wrong content: " + content, !content.contains("${"));
		assertTrue("Wrong content: " + content, !content.contains("_csrf"));
		assertTrue("Wrong content: " + content, !content.contains("%"));
	}

	@Test
	public void testApprovalPageWithScopes() throws Exception {
		request.setContextPath("/foo");
		parameters.put("client_id", "client");
		HashMap<String, Object> model = new HashMap<String, Object>();
		model.put("authorizationRequest", createFromParameters(parameters));
		model.put("scopes", Collections.singletonMap("scope.read", "true"));
		ModelAndView result = endpoint.getAccessConfirmation(model, request);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.contains("scope.read"));
		assertTrue("Wrong content: " + content, content.contains("checked"));
		assertTrue("Wrong content: " + content, content.contains("/foo/oauth/authorize"));
		assertTrue("Wrong content: " + content, !content.contains("${"));
		assertTrue("Wrong content: " + content, !content.contains("_csrf"));
		assertTrue("Wrong content: " + content, !content.contains("%"));
	}

	@Test
	public void testApprovalPageWithCsrf() throws Exception {
		request.setContextPath("/foo");
		request.setAttribute("_csrf", new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "FOO"));
		parameters.put("client_id", "client");
		HashMap<String, Object> model = new HashMap<String, Object>();
		model.put("authorizationRequest", createFromParameters(parameters));
		ModelAndView result = endpoint.getAccessConfirmation(model, request);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.contains("_csrf"));
		assertTrue("Wrong content: " + content, content.contains("/foo/oauth/authorize"));
		assertTrue("Wrong content: " + content, !content.contains("${"));
	}

	// gh-1340
	@Test
	public void testApprovalPageWithSuspectScope() throws Exception {
		request.setContextPath("/foo");
		parameters.put("client_id", "client");
		HashMap<String, Object> model = new HashMap<String, Object>();
		model.put("authorizationRequest", createFromParameters(parameters));
		String scope = "${T(java.lang.Runtime).getRuntime().exec(\"cd ..\")}";
		String escapedScope = "T(java.lang.Runtime).getRuntime().exec(&quot;cd ..&quot;)";
		model.put("scopes", Collections.singletonMap(scope, "true"));
		ModelAndView result = endpoint.getAccessConfirmation(model, request);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, !content.contains(scope));
		assertTrue("Wrong content: " + content, content.contains(escapedScope));
	}

	@Test
	public void testApprovalPageWithScopesInForm() throws Exception {
		String expectedContent = "<html><body><h1>OAuth Approval</h1><p>Do you authorize \"client\" to access your protected resources?</p>" +
				"<form id=\"confirmationForm\" name=\"confirmationForm\" action=\"/foo/oauth/authorize\" method=\"post\">" +
				"<input name=\"user_oauth_approval\" value=\"true\" type=\"hidden\"/><input type=\"hidden\" name=\"_csrf\" value=\"FOO\" /><ul>" +
				"<li><div class=\"form-group\">scope.read: <input type=\"radio\" name=\"scope.read\" value=\"true\" checked>Approve</input> " +
				"<input type=\"radio\" name=\"scope.read\" value=\"false\">Deny</input></div></li></ul><label>" +
				"<input name=\"authorize\" value=\"Authorize\" type=\"submit\"/></label></form></body></html>";
		request.setContextPath("/foo");
		request.setAttribute("_csrf", new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "FOO"));
		parameters.put("client_id", "client");
		HashMap<String, Object> model = new HashMap<String, Object>();
		model.put("authorizationRequest", createFromParameters(parameters));
		model.put("scopes", Collections.singletonMap("scope.read", "true"));
		ModelAndView result = endpoint.getAccessConfirmation(model, request);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.equals(expectedContent));
	}

	@Test
	public void testApprovalPageWithoutScopesInForm() throws Exception {
		String expectedContent = "<html><body><h1>OAuth Approval</h1><p>Do you authorize \"client\" to access your protected resources?</p>" +
				"<form id=\"confirmationForm\" name=\"confirmationForm\" action=\"/foo/oauth/authorize\" method=\"post\">" +
				"<input name=\"user_oauth_approval\" value=\"true\" type=\"hidden\"/><input type=\"hidden\" name=\"_csrf\" value=\"FOO\" /><label>" +
				"<input name=\"authorize\" value=\"Authorize\" type=\"submit\"/></label></form>" +
				"<form id=\"denialForm\" name=\"denialForm\" action=\"/foo/oauth/authorize\" method=\"post\">" +
				"<input name=\"user_oauth_approval\" value=\"false\" type=\"hidden\"/><input type=\"hidden\" name=\"_csrf\" value=\"FOO\" /><label>" +
				"<input name=\"deny\" value=\"Deny\" type=\"submit\"/></label></form></body></html>";
		request.setContextPath("/foo");
		request.setAttribute("_csrf", new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "FOO"));
		parameters.put("client_id", "client");
		HashMap<String, Object> model = new HashMap<String, Object>();
		model.put("authorizationRequest", createFromParameters(parameters));
		ModelAndView result = endpoint.getAccessConfirmation(model, request);
		result.getView().render(result.getModel(), request , response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: " + content, content.equals(expectedContent));
	}
}