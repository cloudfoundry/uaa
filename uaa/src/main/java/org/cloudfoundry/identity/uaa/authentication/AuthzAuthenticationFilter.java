package org.cloudfoundry.identity.uaa.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * Filter which processes authentication submitted through the <code>/authorize</code> endpoint.
 *
 * Checks the submitted information for a parameter named "credentials", in JSON format.
 * <p>
 * If the parameter is found, it will submit an authentication request to the AuthenticationManager and attempt to
 * authenticate the user. If authentication fails, it will return an error message. Otherwise, it creates a security
 * context and allows the request to continue.
 * <p>
 * If the parameter is not present, the filter will have no effect.
 *
 * See <a href="https://github.com/vmware-ac/poc-identity/blob/master/docs/UAA-APIs.md">UUA API Docs</a>
 */
public class AuthzAuthenticationFilter implements Filter {
	private final Log logger = LogFactory.getLog(getClass());
	private AuthenticationManager authenticationManager;
	private ObjectMapper mapper = new ObjectMapper();


	public AuthzAuthenticationFilter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager);
		this.authenticationManager = authenticationManager;
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;

		String credentials = req.getParameter("credentials");

		logger.debug("Credentials " + credentials);

		if (credentials != null) {
			// Keep it simple for now and just use a map of JSON fields to create the authentication request.
			Map<String,String> loginInfo = mapper.readValue(credentials, new TypeReference<Map<String, String>>() {});
			logger.debug("Located credentials in request, with keys: " + loginInfo.keySet());

			try {
				Authentication result = authenticationManager.authenticate(new AuthzAuthenticationRequest(loginInfo));
				SecurityContextHolder.getContext().setAuthentication(result);
			}
			catch (AuthenticationException e) {
				logger.debug("Authentication failed");
				response.getWriter().write("{ \"error\":\"authentication failed\" }");
				response.setContentType("application/json");
				res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}
		}

		chain.doFilter(request, response);
	}

	public void init(FilterConfig filterConfig) throws ServletException {}

	public void destroy() {}
}
