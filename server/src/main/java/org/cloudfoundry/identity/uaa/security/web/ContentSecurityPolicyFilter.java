package org.cloudfoundry.identity.uaa.security.web;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static java.util.Collections.unmodifiableSet;

public class ContentSecurityPolicyFilter extends OncePerRequestFilter {

    private final Set<String> allowedScriptSrc;
    private final String cspHeader;

    public ContentSecurityPolicyFilter(List<String> allowedScriptSrc) {
        this.allowedScriptSrc = unmodifiableSet(new HashSet<>(allowedScriptSrc));
        this.cspHeader = cspHeaderValue();
    }

    @Override
    public void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        response.setHeader("Content-Security-Policy", cspHeader);
        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        final String requestPath = UaaUrlUtils.getRequestPath(request);
        final List<String> pathsWithHtmlInlineScripts = Arrays.asList(
                "/saml/",
                "/saml2/",
                "/login_implicit");

        return pathsWithHtmlInlineScripts.stream()
                .anyMatch(requestPath::startsWith);
    }

    private String cspHeaderValue() {
        StringBuilder b = new StringBuilder();
        b.append("script-src ");
        b.append(String.join(" ", this.allowedScriptSrc));
        return b.toString();
    }
}
