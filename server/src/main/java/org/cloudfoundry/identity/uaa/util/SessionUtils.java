package org.cloudfoundry.identity.uaa.util;

import javax.servlet.http.HttpSession;

public final class SessionUtils {
    public static final String PASSWORD_CHANGE_REQUIRED = "PASSWORD_CHANGE_REQUIRED";

    private SessionUtils() {}

    public static boolean isPasswordChangeRequired(HttpSession session) {
        Object passwordChangeRequired = session.getAttribute(PASSWORD_CHANGE_REQUIRED);

        if (passwordChangeRequired == null) {
            return false;
        }

        if (!(passwordChangeRequired instanceof Boolean)) {
            throw new IllegalArgumentException(String.format("The %s attribute on the session must be a Boolean", PASSWORD_CHANGE_REQUIRED));
        }

        return (Boolean) passwordChangeRequired;
    }

    public static void setPasswordChangeRequired(HttpSession session, boolean passwordChangeRequired) {
        session.setAttribute(PASSWORD_CHANGE_REQUIRED, passwordChangeRequired);
    }
}
