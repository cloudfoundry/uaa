package org.cloudfoundry.identity.uaa.mfa;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpSession;

public class MfaCredentialsSessionCache {

    private static final String SESSION_CREDENTIAL_ATTR_NAME = "SESSION_USER_GOOGLE_MFA_CREDENTIALS";

    public UserGoogleMfaCredentials getCredentials() {
        return (UserGoogleMfaCredentials) session().getAttribute(SESSION_CREDENTIAL_ATTR_NAME);
    }

    public void putCredentials(UserGoogleMfaCredentials creds) {
        session().setAttribute(SESSION_CREDENTIAL_ATTR_NAME, creds);
    }

    public void removeCredentials() {
        session().removeAttribute(SESSION_CREDENTIAL_ATTR_NAME);
    }

    private HttpSession session() {
        HttpSession session = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest().getSession(false);
        if(session == null) {
            throw new RuntimeException("Session not found");
        }
        return session;
    }
}
