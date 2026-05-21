package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DenyAccessToUaaAdviceTest {

    private DenyAccessToUaaAdvice denyAccessToUaaAdvice;
    private IdentityZone identityZone;

    @BeforeEach
    void setUp() {
        denyAccessToUaaAdvice = new DenyAccessToUaaAdvice();
    }

    @Nested
    class WhenIsUaa {
        @BeforeEach
        void setUp() {
            identityZone = IdentityZone.getUaa();
        }

        @Test
        void checkIdentityZone() {
            assertThatThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZone(identityZone))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessage("Access to UAA is not allowed.");
        }

        @Test
        void checkIdentityZoneId() {
            String id = identityZone.getId();
            assertThatThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZoneId(id))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessage("Access to UAA is not allowed.");
        }
    }

    @Nested
    class WhenIsNotUaa {

        @BeforeEach
        void setUp() {
            identityZone = new IdentityZone();
            identityZone.setId("not uaa");
        }

        @Test
        void checkIdentityZone_isNotUaa() {
            assertThatNoException().isThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZone(identityZone));
            assertThatNoException().isThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZone(null));
        }

        @Test
        void checkIdentityZone_zoneWithNullId_isNotUaa() {
            IdentityZone zoneWithNullId = new IdentityZone();
            assertThatNoException().isThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZone(zoneWithNullId));
        }

        @Test
        void checkIdentityZoneId_isNotUaa() {
            assertThatNoException().isThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZoneId(identityZone.getId()));
            assertThatNoException().isThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZoneId(""));
            assertThatNoException().isThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZoneId(null));
        }
    }

    /**
     * On case-insensitive databases (default MySQL collations), a WHERE id = 'UAA' lookup
     * resolves to the system-zone row stored as 'uaa'. These tests verify that the advice
     * blocks all case variants of "uaa", closing the authorization bypass reported in
     * .agent/report.md.
     */
    @Nested
    class WhenZoneIdIsCaseVariantOfUaa {

        @ParameterizedTest(name = "checkIdentityZone blocks id=''{0}''")
        @ValueSource(strings = {"UAA", "Uaa", "uAA", "uAa", "UaA", "UAa"})
        void checkIdentityZone_deniesAccess(String caseVariant) {
            IdentityZone zone = new IdentityZone();
            zone.setId(caseVariant);
            assertThatThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZone(zone))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessage("Access to UAA is not allowed.");
        }

        @ParameterizedTest(name = "checkIdentityZoneId blocks id=''{0}''")
        @ValueSource(strings = {"UAA", "Uaa", "uAA", "uAa", "UaA", "UAa"})
        void checkIdentityZoneId_deniesAccess(String caseVariant) {
            assertThatThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZoneId(caseVariant))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessage("Access to UAA is not allowed.");
        }
    }
}
