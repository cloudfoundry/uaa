package org.cloudfoundry.identity.uaa.scim.exception;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class InvalidPasswordExceptionTest {

    @Test
    public void errorMessagesEmitInSortedOrder() {
        InvalidPasswordException exception = new InvalidPasswordException(Arrays.asList("a2", "b1", "a1"));
        assertEquals("a1 a2 b1", exception.getMessagesAsOneString());
    }
}
