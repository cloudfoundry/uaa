package org.cloudfoundry.identity.uaa.util;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import java.util.Deque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
        assertThatThrownBy(() -> SessionUtils.isPasswordChangeRequired(mockHttpSession)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Nested
    class ConsumeSupersededState {

        private static final String IDP_ORIGIN = "test-idp";
        private static final String STATE_A = "state-aaa";
        private static final String STATE_B = "state-bbb";

        @Test
        void returnsTrueWhenStateIsInSupersededList() {
            SessionUtils.recordSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A);

            assertThat(SessionUtils.consumeSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A)).isTrue();
        }

        @Test
        void removesStateFromSupersededListAfterConsumption() {
            SessionUtils.recordSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A);
            SessionUtils.consumeSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A);

            @SuppressWarnings("unchecked")
            Deque<String> remaining = (Deque<String>) mockHttpSession.getAttribute(
                    SessionUtils.supersededStateParameterAttributeKeyForIdp(IDP_ORIGIN));
            assertThat(remaining).doesNotContain(STATE_A);
        }

        @Test
        void secondCallWithSameStateReturnsFalse() {
            SessionUtils.recordSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A);
            SessionUtils.consumeSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A);

            assertThat(SessionUtils.consumeSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A)).isFalse();
        }

        @Test
        void returnsFalseForUnknownState() {
            SessionUtils.recordSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A);

            assertThat(SessionUtils.consumeSupersededState(mockHttpSession, IDP_ORIGIN, STATE_B)).isFalse();
        }

        @Test
        void doesNotRemoveOtherStatesWhenConsumingOne() {
            SessionUtils.recordSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A);
            SessionUtils.recordSupersededState(mockHttpSession, IDP_ORIGIN, STATE_B);
            SessionUtils.consumeSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A);

            @SuppressWarnings("unchecked")
            Deque<String> remaining = (Deque<String>) mockHttpSession.getAttribute(
                    SessionUtils.supersededStateParameterAttributeKeyForIdp(IDP_ORIGIN));
            assertThat(remaining).contains(STATE_B);
        }

        @Test
        void returnsFalseWhenNoSupersededListExists() {
            assertThat(SessionUtils.consumeSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A)).isFalse();
        }

        @Test
        void returnsFalseForNullState() {
            SessionUtils.recordSupersededState(mockHttpSession, IDP_ORIGIN, STATE_A);

            assertThat(SessionUtils.consumeSupersededState(mockHttpSession, IDP_ORIGIN, null)).isFalse();
        }
    }
}