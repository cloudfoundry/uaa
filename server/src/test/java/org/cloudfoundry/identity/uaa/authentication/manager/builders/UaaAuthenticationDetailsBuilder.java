package org.cloudfoundry.identity.uaa.authentication.manager.builders;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UaaAuthenticationDetailsBuilder {
    private UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);

    private UaaAuthenticationDetailsBuilder() {
        // defaults
        when(uaaAuthenticationDetails.getSessionId()).thenReturn("default_session_id");
    }

    public static UaaAuthenticationDetailsBuilder aUaaAuthenticationDetails() {
        return new UaaAuthenticationDetailsBuilder();
    }

    public UaaAuthenticationDetailsBuilder withOrigin(String origin) {
        when(uaaAuthenticationDetails.getOrigin()).thenReturn(origin);
        return this;
    }

    public UaaAuthenticationDetailsBuilder withClientId(String clientId) {
        when(uaaAuthenticationDetails.getClientId()).thenReturn(clientId);
        return this;
    }

    public UaaAuthenticationDetailsBuilder withSessionId(String sessionId) {
        when(uaaAuthenticationDetails.getSessionId()).thenReturn(sessionId);
        return this;
    }

    public UaaAuthenticationDetails build() {
        return uaaAuthenticationDetails;
    }
}
