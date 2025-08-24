package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class SessionUtilsTest {
    private MockHttpSession mockHttpSession;

    @BeforeEach
    void setUp() {
        mockHttpSession = new MockHttpSession();
    }

    @Test
    void isPasswordChangeRequiredIfNull() {
        assertThat(SessionUtils.isPasswordChangeRequired(mockHttpSession)).isFalse();
    }

    @Test
    void isPasswordChangeRequiredIfSetFalse() {
        SessionUtils.setPasswordChangeRequired(mockHttpSession, false);
        assertThat(SessionUtils.isPasswordChangeRequired(mockHttpSession)).isFalse();
    }

    @Test
    void isPasswordChangeRequiredIfSetTrue() {
        SessionUtils.setPasswordChangeRequired(mockHttpSession, true);
        assertThat(SessionUtils.isPasswordChangeRequired(mockHttpSession)).isTrue();
    }

    @Test
    void isPasswordChangeRequiredIfSetNotBoolean() {
        mockHttpSession.setAttribute(SessionUtils.PASSWORD_CHANGE_REQUIRED, "true");
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> SessionUtils.isPasswordChangeRequired(mockHttpSession));
    }
}