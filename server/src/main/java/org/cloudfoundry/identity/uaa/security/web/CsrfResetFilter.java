package org.cloudfoundry.identity.uaa.security.web;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class CsrfResetFilter extends OncePerRequestFilter{
    private final CsrfTokenRepository tokenRepository;

    public CsrfResetFilter(CsrfTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        CsrfToken newToken = tokenRepository.generateToken(request);
        tokenRepository.saveToken(newToken, request, response);

        request.setAttribute(CsrfToken.class.getName(), newToken);
        request.setAttribute(newToken.getParameterName(), newToken);
        filterChain.doFilter(request, response);
    }
}
