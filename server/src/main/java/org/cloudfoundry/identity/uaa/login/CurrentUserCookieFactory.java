package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import javax.servlet.http.Cookie;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class CurrentUserCookieFactory {
    public String CURRENT_USER_COOKIE_NAME = "Current-User";
    private final boolean secure;
    private int sessionTimeout;

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
