package org.cloudfoundry.identity.uaa.scim.exception;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class InvalidPasswordExceptionTest {

    @Test
    void errorMessagesEmitInSortedOrder() {
        InvalidPasswordException exception = new InvalidPasswordException(Arrays.asList("a2", "b1", "a1"));
        assertThat(exception.getMessagesAsOneString()).isEqualTo("a1 a2 b1");
    }
}
