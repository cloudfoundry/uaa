package org.cloudfoundry.identity.uaa.logging;

import org.junit.Test;

import static org.junit.Assert.*;

public class LogSanitizerUtilTest {

    @Test
    public void testSanitizeInput() {
        assertEquals(LogSanitizerUtil.sanitize("one\ntwo\tthree\rfour"),
                "one|two|three|four[SANITIZED]");
    }

    @Test
    public void testSanitizeCleanInput() {
        assertEquals(LogSanitizerUtil.sanitize("one two three four"),
                "one two three four");
    }
}