package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionUtilsTest {
    private MockHttpSession mockHttpSession;

    @BeforeEach
    void setUp() {
        mockHttpSession = new MockHttpSession();
    }

    @Test
    void isPasswordChangeRequiredIfNull() {
        assertFalse(SessionUtils.isPasswordChangeRequired(mockHttpSession));
    }

    @Test
    void isPasswordChangeRequiredIfSetFalse() {
        SessionUtils.setPasswordChangeRequired(mockHttpSession, false);
        assertFalse(SessionUtils.isPasswordChangeRequired(mockHttpSession));
    }

    @Test
    void isPasswordChangeRequiredIfSetTrue() {
        SessionUtils.setPasswordChangeRequired(mockHttpSession, true);
        assertTrue(SessionUtils.isPasswordChangeRequired(mockHttpSession));
    }

    @Test
    void isPasswordChangeRequiredIfSetNotBoolean() {
        mockHttpSession.setAttribute(SessionUtils.PASSWORD_CHANGE_REQUIRED, "true");
        assertThrows(IllegalArgumentException.class, () -> SessionUtils.isPasswordChangeRequired(mockHttpSession));
    }
}