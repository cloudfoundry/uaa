package org.cloudfoundry.identity.uaa.login;

import org.springframework.security.authentication.AuthenticationDetailsSource;

import javax.servlet.http.HttpServletRequest;

public class SavedRequestAwareAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, SavedRequestAwareAuthenticationDetails> {
    @Override
    public SavedRequestAwareAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new SavedRequestAwareAuthenticationDetails(context);
    }
}
