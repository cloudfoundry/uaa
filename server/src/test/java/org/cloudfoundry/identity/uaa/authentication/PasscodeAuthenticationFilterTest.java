package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter.ExpiringCodeAuthentication;
import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter.ExpiringCodeAuthenticationManager;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.util.MockTimeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;


class PasscodeAuthenticationFilterTest {

    private ExpiringCodeAuthenticationManager manager;

    @Test
    void throwsPasscodeInformationIsMissingInsufficientAuthenticationException() {
        ExpiringCodeAuthentication authentication = new ExpiringCodeAuthentication(null, null);
        try {
            manager.authenticate(authentication);
        } catch (InsufficientAuthenticationException e) {
            assertThat(e.getMessage()).isEqualTo("Passcode information is missing.");
        }
    }

    @Test
    void throwsInvalidPasscodeInsufficientAuthenticationException() {
        ExpiringCodeAuthentication authentication = new ExpiringCodeAuthentication(null, "not empty");
        try {
            manager.authenticate(authentication);
        } catch (InsufficientAuthenticationException e) {
            assertThat(e.getMessage()).isEqualTo("Invalid passcode");
        }
    }

    @BeforeEach
    void setup() {
        Logger logger = LoggerFactory.getLogger(PasscodeAuthenticationFilterTest.class);
        ExpiringCodeStore expiringCodeStore = new InMemoryExpiringCodeStore(new MockTimeService());
        manager = new ExpiringCodeAuthenticationManager(null, null, logger, expiringCodeStore, null);
    }
}