package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
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
        void checkIdentityZoneId_isNotUaa() {
            assertThatNoException().isThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZoneId(identityZone.getId()));
            assertThatNoException().isThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZoneId(""));
            assertThatNoException().isThrownBy(() -> denyAccessToUaaAdvice.checkIdentityZoneId(null));
        }
    }
}
