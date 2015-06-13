package org.cloudfoundry.identity.uaa.scim.exception;

import org.hibernate.validator.internal.util.CollectionHelper;
import org.junit.Test;

import static com.google.common.collect.Lists.newArrayList;
import static org.junit.Assert.*;

public class InvalidPasswordExceptionTest {

    @Test
    public void errorMessagesEmitInSortedOrder() {
        InvalidPasswordException exception = new InvalidPasswordException(newArrayList("a2", "b1", "a1"));
        assertEquals("a1 a2 b1", exception.getMessagesAsOneString());
    }
}
