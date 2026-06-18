package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.SavedRequest;

import jakarta.servlet.http.HttpSession;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;

public final class SessionUtils {
    public static final String PASSWORD_CHANGE_REQUIRED = "PASSWORD_CHANGE_REQUIRED";
    public static final String FORCE_PASSWORD_EXPIRED_USER = "FORCE_PASSWORD_EXPIRED_USER";

    // shadows org.springframework.security.web.savedrequest.HttpSessionRequestCache.SAVED_REQUEST
    //         org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache.DEFAULT_SAVED_REQUEST_ATTR
    //
    public static final String SAVED_REQUEST_SESSION_ATTRIBUTE = "SPRING_SECURITY_SAVED_REQUEST";

    // shadows org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY
    //         org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository.DEFAULT_SPRING_SECURITY_CONTEXT_ATTR_NAME
    //         org.springframework.session.jdbc.JdbcIndexedSessionRepository.SPRING_SECURITY_CONTEXT
    //         org.springframework.session.PrincipalNameIndexResolver.SPRING_SECURITY_CONTEXT
    //         org.springframework.session.security.SpringSessionBackedSessionInformation.SPRING_SECURITY_CONTEXT
    public static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";

    private static final String EXTERNAL_OAUTH_STATE_ATTRIBUTE_PREFIX = "external-oauth-state-";
    private static final String EXTERNAL_OAUTH_CODE_VERIFIER_ATTRIBUTE_PREFIX = "external-oauth-verifier-";
    private static final String EXTERNAL_OAUTH_REDIRECT_URI_ATTRIBUTE_PREFIX = "external-oauth-redirect-uri-";
    private static final String EXTERNAL_OAUTH_SUPERSEDED_STATE_ATTRIBUTE_PREFIX = "external-oauth-superseded-state-";

    /**
     * Upper bound on how many recently-superseded state values we remember per IDP origin.
     * Keeps the session footprint bounded while still tolerating a handful of concurrent tabs.
     */
    private static final int MAX_SUPERSEDED_STATES = 5;

    private SessionUtils() {
    }

    public static boolean isPasswordChangeRequired(HttpSession session) {
        Object passwordChangeRequired = session.getAttribute(PASSWORD_CHANGE_REQUIRED);

        if (passwordChangeRequired == null) {
            return false;
        }

        if (!(passwordChangeRequired instanceof Boolean)) {
            throw new IllegalArgumentException("The %s attribute on the session must be a Boolean".formatted(PASSWORD_CHANGE_REQUIRED));
        }

        return (Boolean) passwordChangeRequired;
    }

    public static void setPasswordChangeRequired(HttpSession session, boolean passwordChangeRequired) {
        session.setAttribute(PASSWORD_CHANGE_REQUIRED, passwordChangeRequired);
    }

    public static void setForcePasswordExpiredUser(HttpSession session, UaaAuthentication uaaAuthentication) {
        session.setAttribute(FORCE_PASSWORD_EXPIRED_USER, uaaAuthentication);
    }

    public static UaaAuthentication getForcePasswordExpiredUser(HttpSession session) {
        return (UaaAuthentication) session.getAttribute(FORCE_PASSWORD_EXPIRED_USER);
    }

    public static void setStateParam(HttpSession session, String stateParamKey, String state) {
        session.setAttribute(stateParamKey, state);
    }

    public static Object getStateParam(HttpSession session, String stateParamKey) {
        return session.getAttribute(stateParamKey);
    }

    /**
     * Records a previously-issued state value that has just been overwritten by a newer login
     * attempt for the same IDP origin (e.g. a second browser tab started the login flow). Only
     * states UAA actually issued end up here, so the callback filter can distinguish a genuine
     * concurrent-login race from a forged/tampered state (which is a CSRF attempt).
     */
    @SuppressWarnings("unchecked")
    public static void recordSupersededState(HttpSession session, String idpOriginKey, String supersededState) {
        if (supersededState == null) {
            return;
        }
        String key = supersededStateParameterAttributeKeyForIdp(idpOriginKey);
        Object existing = session.getAttribute(key);
        Deque<String> supersededStates = existing instanceof Deque
                ? (Deque<String>) existing
                : new ArrayDeque<>();
        supersededStates.remove(supersededState);
        supersededStates.addFirst(supersededState);
        while (supersededStates.size() > MAX_SUPERSEDED_STATES) {
            supersededStates.removeLast();
        }
        session.setAttribute(key, supersededStates);
    }

    /**
     * @return {@code true} if {@code state} was a state UAA issued for this IDP origin that has
     * since been superseded by a newer login attempt — i.e. a concurrent-login race rather than CSRF.
     */
    public static boolean isSupersededState(HttpSession session, String idpOriginKey, String state) {
        if (state == null) {
            return false;
        }
        Object existing = session.getAttribute(supersededStateParameterAttributeKeyForIdp(idpOriginKey));
        return existing instanceof Collection<?> states && states.contains(state);
    }

    public static void setSecurityContext(HttpSession session, SecurityContext context) {
        session.setAttribute(SPRING_SECURITY_CONTEXT, context);
    }

    public static void setSavedRequestSession(HttpSession session, SavedRequest clientRedirectSavedRequest) {
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, clientRedirectSavedRequest);
    }

    public static SavedRequest getSavedRequestSession(HttpSession session) {
        return (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
    }

    public static AuthenticationException getAuthenticationException(HttpSession session) {
        return (AuthenticationException) session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }

    public static String stateParameterAttributeKeyForIdp(String idpOriginKey) {
        return EXTERNAL_OAUTH_STATE_ATTRIBUTE_PREFIX + idpOriginKey;
    }

    public static String codeVerifierParameterAttributeKeyForIdp(String idpOriginKey) {
        return EXTERNAL_OAUTH_CODE_VERIFIER_ATTRIBUTE_PREFIX + idpOriginKey;
    }

    public static String redirectUriParameterAttributeKeyForIdp(String idpOriginKey) {
        return EXTERNAL_OAUTH_REDIRECT_URI_ATTRIBUTE_PREFIX + idpOriginKey;
    }

    public static String supersededStateParameterAttributeKeyForIdp(String idpOriginKey) {
        return EXTERNAL_OAUTH_SUPERSEDED_STATE_ATTRIBUTE_PREFIX + idpOriginKey;
    }
}
