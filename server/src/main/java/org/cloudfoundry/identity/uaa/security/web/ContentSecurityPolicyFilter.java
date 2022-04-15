package org.cloudfoundry.identity.uaa.security.web;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

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
        final String requestPath = UaaUrlUtils.getRequestPath(request);
        final List<String> pathsWithHtmlInlineScripts = Arrays.asList(
                "/saml/",
                "/login_implicit",
                "/login/mfa/");

        return pathsWithHtmlInlineScripts.stream()
                .anyMatch(requestPath::startsWith);
    }
}
