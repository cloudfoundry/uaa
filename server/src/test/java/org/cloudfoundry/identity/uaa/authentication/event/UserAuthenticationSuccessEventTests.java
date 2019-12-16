package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.mock;

class UserAuthenticationSuccessEventTests {

    @Test
    void getOriginFromRequest() {
        MockHttpSession session = new MockHttpSession(null, "the-id");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth/authorize");
        request.setSession(session);
        request.setRemoteAddr("127.10.10.10");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, "client-id");

        UserAuthenticationSuccessEvent event = new UserAuthenticationSuccessEvent(mock(UaaUser.class),
                mock(Authentication.class),
                "foobar");
        String origin = event.getOrigin(details);

        assertThat(origin, containsString("remoteAddress=127.10.10.10"));
        assertThat(origin, containsString("clientId=client-id"));
        assertThat(origin, containsString("sessionId=<SESSION>"));
    }
}