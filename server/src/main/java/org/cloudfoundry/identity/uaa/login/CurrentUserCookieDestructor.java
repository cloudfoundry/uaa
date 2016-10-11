package org.cloudfoundry.identity.uaa.login;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CurrentUserCookieDestructor implements AuthenticationFailureHandler, LogoutHandler {
    private AuthenticationFailureHandler delegate;

    public CurrentUserCookieDestructor(AuthenticationFailureHandler delegate) {
        this.delegate = delegate;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        addCookie(response);
        delegate.onAuthenticationFailure(request, response, exception);
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        addCookie(response);
    }

    private void addCookie(HttpServletResponse response) {
        Cookie currentUserCookie = new Cookie("Current-User", "");
        currentUserCookie.setHttpOnly(false);
        currentUserCookie.setMaxAge(0);
        response.addCookie(currentUserCookie);
    }
}
