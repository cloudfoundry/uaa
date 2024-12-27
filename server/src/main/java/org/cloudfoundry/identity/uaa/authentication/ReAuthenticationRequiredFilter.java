package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ReAuthenticationRequiredFilter extends OncePerRequestFilter {

    private final String samlEntityID;

    public ReAuthenticationRequiredFilter(final @Qualifier("samlEntityID") String samlEntityID) {
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
        if (request.getParameter("max_age") != null && SecurityContextHolder.getContext().getAuthentication() instanceof UaaAuthentication) {
            UaaAuthentication auth = (UaaAuthentication) SecurityContextHolder.getContext().getAuthentication();
            if ((System.currentTimeMillis() - auth.getAuthenticatedTime()) > (Long.valueOf(request.getParameter("max_age")) * 1000)) {
                reAuthenticationRequired = true;
                requestParams.remove("max_age");
            }
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
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUrl);
        for (String key : params.keySet()) {
            builder.queryParam(key, params.get(key));
        }
        response.sendRedirect(builder.build().toUriString());
    }
}
