package org.cloudfoundry.identity.uaa.authentication;

import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.CurrentUserCookieFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpHeaders.SET_COOKIE;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;

public class CurrentUserCookieRequestFilter extends OncePerRequestFilter {

    public static final String CURRENT_USER_COOKIE_ERROR = "current_user_cookie_error";
    private final Rfc6265CookieProcessor rfc6265CookieProcessor;
    private final Logger logger = LoggerFactory.getLogger(CurrentUserCookieRequestFilter.class);

    private final CurrentUserCookieFactory currentUserCookieFactory;

    public CurrentUserCookieRequestFilter(CurrentUserCookieFactory currentUserCookieFactory) {
        this.currentUserCookieFactory = currentUserCookieFactory;

        rfc6265CookieProcessor = new Rfc6265CookieProcessor();
        rfc6265CookieProcessor.setSameSiteCookies("Strict");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (isAuthenticated()) {
            UaaPrincipal principal = (UaaPrincipal) getContext().getAuthentication().getPrincipal();
            try {
                Cookie currentUserCookie = currentUserCookieFactory.getCookie(principal);
                String headerValue = rfc6265CookieProcessor.generateHeader(currentUserCookie, request);
                response.addHeader(SET_COOKIE, headerValue);
            } catch (CurrentUserCookieFactory.CurrentUserCookieEncodingException e) {
                logger.error(errorMessage(principal), e);
                handleError(response, principal);
                return;
            }
        } else {
            Cookie currentUserCookie = currentUserCookieFactory.getNullCookie();
            response.addCookie(currentUserCookie);
        }

        filterChain.doFilter(request, response);
    }

    private String errorMessage(UaaPrincipal principal) {
        return "There was a problem while creating the Current-User cookie for user id %s".formatted(principal.getId());
    }

    private void handleError(HttpServletResponse response, UaaPrincipal principal) throws IOException {
        int status = HttpStatus.INTERNAL_SERVER_ERROR.value();
        UaaException error = new UaaException(CURRENT_USER_COOKIE_ERROR, errorMessage(principal), status);

        response.setStatus(status);
        response.getWriter().write(JsonUtils.writeValueAsString(error));
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
    }

    private boolean isAuthenticated() {
        Authentication authentication = getContext().getAuthentication();
        return authentication != null &&
                authentication instanceof UaaAuthentication ua &&
                ua.isAuthenticated();
    }
}
