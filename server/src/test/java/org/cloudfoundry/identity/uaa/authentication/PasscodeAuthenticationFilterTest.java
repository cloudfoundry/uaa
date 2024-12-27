package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter.ExpiringCodeAuthentication;
import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter.ExpiringCodeAuthenticationManager;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.util.MockTimeService;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import static org.junit.jupiter.api.Assertions.assertEquals;


public class PasscodeAuthenticationFilterTest {

    private ExpiringCodeAuthenticationManager manager;

    @Test
    public void throwsPasscodeInformationIsMissingInsufficientAuthenticationException() {
        ExpiringCodeAuthentication authentication = new ExpiringCodeAuthentication(null, null);
        try {
            manager.authenticate(authentication);
        } catch (InsufficientAuthenticationException e) {
            assertEquals("Passcode information is missing.", e.getMessage());
        }
    }

    @Test
    public void throwsInvalidPasscodeInsufficientAuthenticationException() {
        ExpiringCodeAuthentication authentication = new ExpiringCodeAuthentication(null, "not empty");
        try {
            manager.authenticate(authentication);
        } catch (InsufficientAuthenticationException e) {
            assertEquals("Invalid passcode", e.getMessage());
        }
    }

    @Before
    public void setup() {
        Logger logger = LoggerFactory.getLogger(ExpiringCodeAuthenticationManager.class);
        ExpiringCodeStore expiringCodeStore = new InMemoryExpiringCodeStore(new MockTimeService());
        manager = new ExpiringCodeAuthenticationManager(null, null, logger, expiringCodeStore, null);
    }
}