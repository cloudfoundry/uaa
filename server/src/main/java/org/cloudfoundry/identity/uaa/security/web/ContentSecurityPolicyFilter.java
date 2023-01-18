package org.cloudfoundry.identity.uaa.security.web;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public class ContentSecurityPolicyFilter extends OncePerRequestFilter {

    private ContentSecurityPolicyConfiguration configuration = new ContentSecurityPolicyConfiguration();
    private String cspHeader = null;

    @Override
    public void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // If cspHeader were set when the class was instantiated, it would use
        // the values in `configuration` before they're possibly overwritten
        // by spring-servlet.xml, which itself reads values from uaa.yml. To
        // avoid this, we set it lazily here instead.
        if (this.cspHeader == null) {
            cspHeader = cspHeaderValue();
        }
        response.setHeader("Content-Security-Policy", cspHeader);
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

    private String cspHeaderValue() {
        StringBuilder b = new StringBuilder();
        b.append("script-src ");
        b.append(String.join(" ", configuration.getAllowedScriptSrc()));
        return b.toString();
    }

    public void setCspAllowedScriptSrc(List<String> cspAllowedScriptSrc) {
        this.configuration.setAllowedScriptSrc(new HashSet<String>(cspAllowedScriptSrc));
    }
}
