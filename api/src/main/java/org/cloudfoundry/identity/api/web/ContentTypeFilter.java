package org.cloudfoundry.identity.api.web;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class ContentTypeFilter implements Filter {
	
	private Map<String,String> mediaTypes = new HashMap<String, String>();
	
	public void setMediaTypes(Map<String, String> mediaTypes) {
		this.mediaTypes = mediaTypes;
	}

	public void destroy() {
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		
		for (String path : mediaTypes.keySet()) {
			if (matches(httpServletRequest, path)) {
				response.setContentType(mediaTypes.get(path));
				 break;
			}
		}
		chain.doFilter(request, response);
	}

	public void init(FilterConfig config) throws ServletException {
	}

	   private boolean matches(HttpServletRequest request, String path) {
	        String uri = request.getRequestURI();
	        int pathParamIndex = uri.indexOf(';');

	        if (pathParamIndex > 0) {
	            // strip everything after the first semi-colon
	            uri = uri.substring(0, pathParamIndex);
	        }

	        if ("".equals(request.getContextPath())) {
	            return uri.endsWith(path);
	        }

	        return uri.endsWith(request.getContextPath() + path);
	    }
}
