package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import javax.servlet.http.Cookie;
import java.net.URLEncoder;

public class CurrentUserCookieFactory {
    private int sessionTimeout;
    public String CURRENT_USER_COOKIE_NAME = "Current-User";

    public CurrentUserCookieFactory(int sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
    }

    public Cookie getCookie(UaaPrincipal uaaPrincipal) throws CurrentUserCookieEncodingException {
        CurrentUserInformation currentUserInformation = new CurrentUserInformation();
        currentUserInformation.setUserId(uaaPrincipal.getId());
        Cookie cookie = new Cookie(CURRENT_USER_COOKIE_NAME, urlEncode(JsonUtils.writeValueAsString(currentUserInformation)));
        cookie.setPath("/");
        cookie.setHttpOnly(false);
        cookie.setMaxAge(sessionTimeout);
        return cookie;
    }

    private String urlEncode(String value) throws CurrentUserCookieEncodingException {
        try {
            return URLEncoder.encode(value, "UTF-8");
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
