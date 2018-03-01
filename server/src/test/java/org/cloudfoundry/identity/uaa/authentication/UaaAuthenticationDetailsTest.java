package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class UaaAuthenticationDetailsTest {

    @Test
    public void testToStringDoesNotContainSessionId() {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(false, "clientid", "origin", "1234");
        String toString = details.toString();
        assertTrue(toString.contains("sessionId=<SESSION>"));
    }
}