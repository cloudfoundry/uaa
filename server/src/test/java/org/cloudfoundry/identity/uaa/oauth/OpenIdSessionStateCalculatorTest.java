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
    public void setup() {
        calculator = new OpenIdSessionStateCalculator();
        SecureRandom secureRandom = mock(SecureRandom.class);
        doNothing().when(secureRandom).nextBytes(any());
        calculator.setSecureRandom(secureRandom);
    }

    @Test
    public void calculate() {
            String sessionState = calculator.calculate("current-user-id", "client_id", "http://example.com");
        assertEquals("3b501628aea599d810e86e06884fd5a468b91a7a1c05c5a0b7211b553ec4aa02.0000000000000000000000000000000000000000000000000000000000000000", sessionState);
    }

    @Test
    public void calculate_shouldChangeSessionIdChanges() {
        String sessionState = calculator.calculate("current-user-id2", "client_id", "http://example.com");
        assertEquals("8ccaa974ff0d15740285da892a1296ff4cebcf6dfcc4b76bd36e76565aadf3df.0000000000000000000000000000000000000000000000000000000000000000", sessionState);
    }

    @Test
    public void calculate_shouldChangeClientIdChanges() {
        String sessionState = calculator.calculate("current-user-id", "client_id2", "http://example.com");
        assertEquals("cfe7afa30be40cc680db7e0311b7cb559381995632477f05f66d7d88f905a6f4.0000000000000000000000000000000000000000000000000000000000000000", sessionState);
    }
}