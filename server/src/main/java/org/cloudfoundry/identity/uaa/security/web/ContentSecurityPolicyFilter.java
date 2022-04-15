package org.cloudfoundry.identity.uaa.security.web;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
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

        response.setHeader("Content-Security-Policy",
                "script-src 'self' 'unsafe-inline'");
        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = UaaUrlUtils.getRequestPath(request);

        return path.startsWith("/saml/");
    }
}
