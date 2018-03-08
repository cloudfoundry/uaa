package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


public class ReAuthenticationRequiredFilter extends OncePerRequestFilter {
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
            if ((System.currentTimeMillis() - auth.getAuthenticatedTime()) > (Long.valueOf(request.getParameter("max_age"))*1000)) {
                reAuthenticationRequired = true;
                requestParams.remove("max_age");
            }
        }
        if (reAuthenticationRequired) {
            request.getSession().invalidate();
            sendRedirect("/", requestParams, request, response);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    protected void sendRedirect(String redirectUrl, Map<String, String[]> params, HttpServletRequest request, HttpServletResponse response) throws IOException {
        StringBuilder url = new StringBuilder(
                redirectUrl.startsWith("/") ? request.getContextPath() : ""
        );
        url.append(redirectUrl);
        boolean firstElement = true;
        for (String key : params.keySet()) {
            String[] values = params.get(key);
            for (String value : values) {
                if (firstElement) {
                    firstElement = false;
                    url.append("?");
                } else {
                    url.append("&");
                }
                url.append(key + "=" + value);
            }
        }
        response.sendRedirect(url.toString());
    }
}
