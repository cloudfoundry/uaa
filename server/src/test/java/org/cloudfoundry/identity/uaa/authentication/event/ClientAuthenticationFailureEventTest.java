package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class ClientAuthenticationFailureEventTest {
    @Test
    void getAuditEvent() {
        UaaAuthenticationDetails authDetails = mock(UaaAuthenticationDetails.class);
        Authentication authentication = mock(Authentication.class);
        doReturn(authDetails).when(authentication).getDetails();
        doReturn("method").when(authDetails).getAuthenticationMethod();
        doReturn("clientid").when(authDetails).getClientId();
        ClientAuthenticationFailureEvent event = new ClientAuthenticationFailureEvent(authentication, new BadCredentialsException("exception", new IllegalArgumentException("illegal argument")), "uaa");
        assertThat(event.getAuditEvent()).isNotNull();
        assertThat(event.getDetailedDescription()).contains("illegal argument");
    }
}
