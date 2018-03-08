package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class ReAuthenticationRequiredFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        boolean reAuthenticationRequired = false;
        if ("login".equals(request.getParameter("prompt"))) {
            reAuthenticationRequired = true;
        }
        if (request.getParameter("max_age") != null && SecurityContextHolder.getContext().getAuthentication() instanceof UaaAuthentication) {
            UaaAuthentication auth = (UaaAuthentication) SecurityContextHolder.getContext().getAuthentication();
            if ((System.currentTimeMillis() - auth.getAuthenticatedTime()) > (Long.valueOf(request.getParameter("max_age"))*1000)) {
                reAuthenticationRequired = true;
            }
        }
        filterChain.doFilter(request, response);
    }
}
