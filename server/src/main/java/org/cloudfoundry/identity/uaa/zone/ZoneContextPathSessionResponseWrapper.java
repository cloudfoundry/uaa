package org.cloudfoundry.identity.uaa.zone;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.util.Locale;

/**
 * Response wrapper that blocks downstream code from clearing the JSESSIONID cookie
 * (so other context-path sub-sessions are not affected).
 */
public class ZoneContextPathSessionResponseWrapper extends HttpServletResponseWrapper {

    private static final String SET_COOKIE_HEADER = "Set-Cookie";

    public ZoneContextPathSessionResponseWrapper(HttpServletResponse response) {
        super(response);
    }

    private HttpServletResponse getHttpResponse() {
        return (HttpServletResponse) getResponse();
    }

    @Override
    public void addCookie(Cookie cookie) {
        if (wouldClearJSessionIdCookie(cookie.getName(), cookie.getValue(), cookie.getMaxAge())) {
            return;
        }
        getHttpResponse().addCookie(cookie);
    }

    @Override
    public void addHeader(String name, String value) {
        if (SET_COOKIE_HEADER.equalsIgnoreCase(name) && wouldClearJSessionIdInHeader(value)) {
            return;
        }
        getHttpResponse().addHeader(name, value);
    }

    @Override
    public void setHeader(String name, String value) {
        if (SET_COOKIE_HEADER.equalsIgnoreCase(name) && wouldClearJSessionIdInHeader(value)) {
            return;
        }
        getHttpResponse().setHeader(name, value);
    }

    private boolean wouldClearJSessionIdCookie(String name, String value, int maxAge) {
        if (!ZoneContextPathSessionFilter.JSESSIONID.equalsIgnoreCase(name)) {
            return false;
        }
        return maxAge == 0 || (value != null && value.isEmpty());
    }

    private boolean wouldClearJSessionIdInHeader(String headerValue) {
        if (headerValue == null || headerValue.isEmpty()) {
            return false;
        }
        int eq = headerValue.indexOf('=');
        if (eq <= 0) {
            return false;
        }
        String name = headerValue.substring(0, eq).trim();
        if (!ZoneContextPathSessionFilter.JSESSIONID.equalsIgnoreCase(name)) {
            return false;
        }
        String valuePart = eq < headerValue.length() - 1 ? headerValue.substring(eq + 1) : "";
        int semicolon = valuePart.indexOf(';');
        String value = (semicolon < 0 ? valuePart : valuePart.substring(0, semicolon)).trim();
        if (value.isEmpty()) {
            return true;
        }
        String rest = semicolon < 0 ? "" : valuePart.substring(semicolon);
        return rest.toLowerCase(Locale.ROOT).contains("max-age=0");
    }
}
