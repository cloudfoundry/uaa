package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationTargetUrlRequestHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AccountSavingAuthenticationSuccessHandler extends AbstractAuthenticationTargetUrlRequestHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        Object principal = authentication.getPrincipal();

        if(!(principal instanceof UaaPrincipal)) {
            throw new IllegalArgumentException("Unrecognized authentication principle.");
        }

        UaaPrincipal uaaPrincipal = (UaaPrincipal) principal;
        SavedAccountOption savedAccountOption = new SavedAccountOption();
        savedAccountOption.setEmail(uaaPrincipal.getEmail());
        savedAccountOption.setOrigin(uaaPrincipal.getOrigin());
        savedAccountOption.setUserId(uaaPrincipal.getId());
        savedAccountOption.setUsername(uaaPrincipal.getName());
        Cookie cookie = new Cookie("Saved-Account-" + uaaPrincipal.getId(), JsonUtils.writeValueAsString(savedAccountOption));

        cookie.setPath(request.getContextPath() + "/login");
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        // cookie expires in a year
        cookie.setMaxAge(365*24*60*60);

        response.addCookie(cookie);

        handle(request, response, authentication);
    }
}
