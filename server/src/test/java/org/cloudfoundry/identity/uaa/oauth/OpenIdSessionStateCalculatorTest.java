package org.cloudfoundry.identity.uaa.oauth;


import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;

public class OpenIdSessionStateCalculatorTest {

    private OpenIdSessionStateCalculator calculator;

    @Before
    public void setup() throws Exception {
        String uaaUrl = "http://localhost:8080";
        calculator = new OpenIdSessionStateCalculator(uaaUrl);
        SecureRandom secureRandom = mock(SecureRandom.class);
        doNothing().when(secureRandom).nextBytes(any());
        calculator.setSecureRandom(secureRandom);
    }

    @Test
    public void calculate() throws Exception {
        String sessionState = calculator.calculate("session_id", "client_id", "http://example.com");
        assertEquals("b6d594e481f023303f2dd9e41af3c653564b34363f6dc0b5a5555fd31d8f56b4.0000000000000000000000000000000000000000000000000000000000000000", sessionState);
    }

    @Test
    public void calculate_shouldChangeSessionIdChanges() {
        String sessionState = calculator.calculate("session_id2", "client_id", "http://example.com");
        assertEquals("74992895f9312791755774d9ca7d175352ac7e10803631d23c5e79d228d881b4.0000000000000000000000000000000000000000000000000000000000000000", sessionState);
    }

    @Test
    public void calculate_shouldChangeClientIdChanges() {
        String sessionState = calculator.calculate("session_id", "client_id2", "http://example.com");
        assertEquals("757191b323b642b37d4975bffaafefacc0b1d0386eb97c1983a3c8d18d0d3a13.0000000000000000000000000000000000000000000000000000000000000000", sessionState);
    }
}