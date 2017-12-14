package org.cloudfoundry.identity.uaa.oauth;


import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;

public class OpenIdSessionStateCalculatorTest {

    @Test
    public void calculate() throws Exception {
        SecureRandom secureRandom = mock(SecureRandom.class);
        doNothing().when(secureRandom).nextBytes(any());

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(true, "client-id", "origin", "session-id");
        OpenIdSessionStateCalculator openIdSessionState = new OpenIdSessionStateCalculator(details, secureRandom);

        String sessionState = openIdSessionState.calculate();
        assertEquals("8d6dea62907d8796ffbed3c000cb7cdb9f3e3295545df54da940d7196917b653.0000000000000000000000000000000000000000000000000000000000000000", sessionState);
    }
}