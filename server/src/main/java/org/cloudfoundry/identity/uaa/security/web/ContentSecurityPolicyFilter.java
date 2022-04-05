package org.cloudfoundry.identity.uaa.security.web;

import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ContentSecurityPolicyFilter extends OncePerRequestFilter {
    @Override
    public void doFilterInternal(HttpServletRequest request,
                                 HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String requestURI = request.getRequestURI();
        boolean isSamlRequest = request.getRequestURI().contains("/saml/idp") ||
                requestURI.contains("/saml/login");

        if (isSamlRequest) {
            response.setHeader("Content-Security-Policy",
                    "script-src 'self' 'unsafe-inline'");
        } else {
            response.setHeader("Content-Security-Policy",
                    "script-src 'self'");
        }

        chain.doFilter(request, response);
    }
}
