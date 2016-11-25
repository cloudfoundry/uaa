package org.cloudfoundry.identity.uaa.authentication.rememberme;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;

/**
 * The RME cookie will be automatically set when the SAML authentication succeed.
 * 
 * @author Stephane CIZERON
 *
 */
public class SamlLoginRememberMeAwareFilter implements Filter {

	private Boolean enabledForSaml;
	
	public SamlLoginRememberMeAwareFilter() {
	 this(Boolean.TRUE);
	}
	
	public SamlLoginRememberMeAwareFilter(Boolean enabled) {
		this.enabledForSaml = (enabled != null) ? enabled : Boolean.TRUE;
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		chain.doFilter(this.enabledForSaml ? new RememberMeRequestWrapper((HttpServletRequest) request) : request, response);
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		this.enabledForSaml = Boolean.valueOf(filterConfig.getInitParameter("enabledForSaml"));
	}
	
	@Override
	public void destroy() {
	}
	
	/**
	 * This request wrapper returns true when the RememberService needs to detect if the RME is desired.
	 * 
	 */
	public class RememberMeRequestWrapper extends HttpServletRequestWrapper {

		private static final String ENABLED = "true";

		/**
		 * 
		 * @param request
		 */
		public RememberMeRequestWrapper(HttpServletRequest request) {
			super(request);
		}
	
		@Override
       public String getParameter(String name) {
           if (AbstractRememberMeServices.DEFAULT_PARAMETER.equals(name)) {
               return ENABLED;
           } 
           return super.getParameter(name);
       }
	}
}