package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

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
            assertThrowsWithMessageThat(AccessDeniedException.class,
                    () -> denyAccessToUaaAdvice.checkIdentityZone(identityZone),
                    is("Access to UAA is not allowed."));
        }

        @Test
        void checkIdentityZoneId() {

            assertThrowsWithMessageThat(AccessDeniedException.class,
                    () -> denyAccessToUaaAdvice.checkIdentityZoneId(identityZone.getId()),
                    is("Access to UAA is not allowed."));
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
            assertDoesNotThrow(() -> denyAccessToUaaAdvice.checkIdentityZone(identityZone));
            assertDoesNotThrow(() -> denyAccessToUaaAdvice.checkIdentityZone(null));
        }

        @Test
        void checkIdentityZoneId_isNotUaa() {
            assertDoesNotThrow(() -> denyAccessToUaaAdvice.checkIdentityZoneId(identityZone.getId()));
            assertDoesNotThrow(() -> denyAccessToUaaAdvice.checkIdentityZoneId(""));
            assertDoesNotThrow(() -> denyAccessToUaaAdvice.checkIdentityZoneId(null));
        }
    }
}