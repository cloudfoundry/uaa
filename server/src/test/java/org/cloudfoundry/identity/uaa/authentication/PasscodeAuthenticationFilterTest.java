package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter.ExpiringCodeAuthentication;
import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter.ExpiringCodeAuthenticationManager;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.passcode.PasscodeInformation;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.util.MockTimeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;

import java.sql.Timestamp;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


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

    @Nested
    class PasscodeIntent {

        private static final String USER_ID = "user-id-1";

        private ExpiringCodeStore expiringCodeStore;
        private UaaUserDatabase userDatabase;
        private ExpiringCodeAuthenticationManager passcodeManager;

        @BeforeEach
        void setUp() {
            expiringCodeStore = new InMemoryExpiringCodeStore(new MockTimeService());
            userDatabase = mock(UaaUserDatabase.class);
            UaaUser user = mock(UaaUser.class);
            doReturn(List.of()).when(user).getAuthorities();
            when(userDatabase.retrieveUserById(USER_ID)).thenReturn(user);
            passcodeManager = new ExpiringCodeAuthenticationManager(
                    userDatabase, null, LoggerFactory.getLogger(PasscodeAuthenticationFilterTest.class), expiringCodeStore, null);
        }

        private String storePasscode(String intent) {
            PasscodeInformation information = new PasscodeInformation(USER_ID, "marissa", "unused", "uaa", List.of());
            return expiringCodeStore.generateCode(
                    JsonUtils.writeValueAsString(information),
                    new Timestamp(System.currentTimeMillis() + 60_000),
                    intent,
                    IdentityZoneHolder.get().getId()).getCode();
        }

        private ExpiringCodeAuthentication authenticationFor(String passcode) {
            return new ExpiringCodeAuthentication(
                    new PasscodeAuthenticationFilter.PasscodeHttpServletRequest(new MockHttpServletRequest("POST", "/oauth/token")),
                    passcode);
        }

        @Test
        void passcodeWithItsOwnIntentSignsIn() {
            String passcode = storePasscode("PASSCODE " + USER_ID);

            Authentication result = passcodeManager.authenticate(authenticationFor(passcode));

            assertThat(result.getPrincipal()).hasFieldOrPropertyWithValue("id", USER_ID);
        }

        @ParameterizedTest
        @NullSource
        @ValueSource(strings = {"", "EMAIL", "AUTOLOGIN", "PASSCODE", "PASSCODE other-user-id", "passcode user-id-1", "my-application-code"})
        void codeWithAnyOtherIntentIsRejected(String intent) {
            String passcode = storePasscode(intent);

            assertThatThrownBy(() -> passcodeManager.authenticate(authenticationFor(passcode)))
                    .isInstanceOf(InsufficientAuthenticationException.class)
                    .hasMessage("Invalid passcode");
        }
    }
}
