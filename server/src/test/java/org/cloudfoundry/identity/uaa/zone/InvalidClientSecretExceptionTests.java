package org.cloudfoundry.identity.uaa.zone;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class InvalidClientSecretExceptionTests {
    @Test
    public void getMessagesAsOneString() {
        String msg1 = "Message 1.";
        String msg2 = "Message 2.";
        InvalidClientSecretException exception = new InvalidClientSecretException(Arrays.asList(msg1,msg2));
        assertEquals(msg1+" "+msg2, exception.getMessagesAsOneString());
        assertEquals(msg1+" "+msg2, exception.getMessage());
    }

}