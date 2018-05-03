package org.cloudfoundry.identity.uaa.security.web;

import org.junit.Test;

import java.util.regex.Pattern;

import static org.junit.Assert.assertTrue;

public class TimeLimitRegexMatcherTest {

    @Test(expected = TimeLimitRegexMatcher.RegExTimeoutException.class)
    public void testTimeLimitRegexMatcherTimeout() {
        Pattern pattern = Pattern.compile("((a*b*)*) | ((a*)*)");
        String largeString = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaax";
        TimeLimitRegexMatcher.matcher(pattern, largeString).find();
    }

    @Test
    public void testTimeLimitRegexMatcherMatches() {
        Pattern pattern = Pattern.compile("a*");
        String largeString = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaax";
        assertTrue(TimeLimitRegexMatcher.matcher(pattern, largeString).find());
    }
}
