package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredException;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache;
import org.springframework.security.core.context.SecurityContext;

import javax.servlet.http.HttpSession;

public final class SessionUtils {
    public static final String PASSWORD_CHANGE_REQUIRED = "PASSWORD_CHANGE_REQUIRED";
    public static final String FORCE_PASSWORD_EXPIRED_USER = "FORCE_PASSWORD_EXPIRED_USER";
    public static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";
    public static final String SAVED_REQUEST_SESSION_ATTRIBUTE = "SPRING_SECURITY_SAVED_REQUEST";

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

    public static void setForcePasswordExpiredUser(HttpSession session, PasswordChangeRequiredException exception) {
        session.setAttribute(FORCE_PASSWORD_EXPIRED_USER, exception.getAuthentication());
    }

    public static void setStateParam(HttpSession session, String stateParamKey, String state) {
        session.setAttribute(stateParamKey, state);
    }

    public static Object getStateParam(HttpSession session, String stateParamKey) {
        return session.getAttribute(stateParamKey);
    }

    public static void setSecurityContext(HttpSession session, SecurityContext context) {
        session.setAttribute(SPRING_SECURITY_CONTEXT, context);
    }

    public static void setClientRedirectSavedRequest(HttpSession session, UaaSavedRequestCache.ClientRedirectSavedRequest clientRedirectSavedRequest) {
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, clientRedirectSavedRequest);
    }
}
