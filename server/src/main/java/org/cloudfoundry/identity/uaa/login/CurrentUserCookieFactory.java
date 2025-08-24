package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.UaaProperties;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import jakarta.servlet.http.Cookie;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CurrentUserCookieFactory {
    public String CURRENT_USER_COOKIE_NAME = "Current-User";
    private final boolean secure;
    private final int sessionTimeout;

    @Autowired
    public CurrentUserCookieFactory(UaaProperties.Servlet servletProps, UaaProperties.RootLevel rootProps) {
        this(Optional.ofNullable(servletProps.sessionCookie().maxAge()).orElse(1800), rootProps.require_https());
    }

    public CurrentUserCookieFactory(int sessionTimeout, boolean secure) {
        this.sessionTimeout = sessionTimeout;
        this.secure = secure;
    }

    public Cookie getCookie(UaaPrincipal uaaPrincipal) throws CurrentUserCookieEncodingException {
        CurrentUserInformation currentUserInformation = new CurrentUserInformation();
        currentUserInformation.setUserId(uaaPrincipal.getId());
        Cookie cookie = new Cookie(CURRENT_USER_COOKIE_NAME, urlEncode(JsonUtils.writeValueAsString(currentUserInformation)));
        cookie.setPath("/");
        cookie.setHttpOnly(false);
        cookie.setSecure(secure);
        cookie.setMaxAge(sessionTimeout);
        return cookie;
    }

    private String urlEncode(String value) throws CurrentUserCookieEncodingException {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CurrentUserCookieEncodingException(e);
        }
    }

    public Cookie getNullCookie() {
        Cookie currentUserCookie = new Cookie(CURRENT_USER_COOKIE_NAME, null);
        currentUserCookie.setHttpOnly(false);
        currentUserCookie.setMaxAge(0);
        currentUserCookie.setPath("/");
        return currentUserCookie;
    }

    public class CurrentUserCookieEncodingException extends Exception {
        public CurrentUserCookieEncodingException(Exception e) {
            super(e);
        }
    }
}
