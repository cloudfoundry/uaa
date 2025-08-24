package org.cloudfoundry.identity.uaa.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ReAuthenticationRequiredFilter extends OncePerRequestFilter {

    private final String samlEntityID;

    public ReAuthenticationRequiredFilter(String samlEntityID) {
        this.samlEntityID = samlEntityID;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        boolean reAuthenticationRequired = false;
        HashMap<String, String[]> requestParams = new HashMap<>(request.getParameterMap());
        if ("login".equals(request.getParameter("prompt"))) {
            reAuthenticationRequired = true;
            requestParams.remove("prompt");
        }
        if (request.getParameter("max_age") != null
            && SecurityContextHolder.getContext().getAuthentication() instanceof UaaAuthentication auth
            && (System.currentTimeMillis() - auth.getAuthenticatedTime()) > (Long.parseLong(request.getParameter("max_age")) * 1000))
        {
                reAuthenticationRequired = true;
                requestParams.remove("max_age");
        }
        if (reAuthenticationRequired) {
            request.getSession().invalidate();
            sendRedirect(request.getRequestURL().toString(), requestParams, response);
        } else {
            if (request.getServletPath().startsWith("/saml/SingleLogout/alias/" + samlEntityID)) {
                CsrfFilter.skipRequest(request);
            }
            filterChain.doFilter(request, response);
        }
    }

    private void sendRedirect(String redirectUrl, Map<String, String[]> params, HttpServletResponse response) throws IOException {
        UriComponentsBuilder builder = UaaUrlUtils.fromUriString(redirectUrl);
        params.forEach(builder::queryParam);
        response.sendRedirect(builder.build().toUriString());
    }
}
