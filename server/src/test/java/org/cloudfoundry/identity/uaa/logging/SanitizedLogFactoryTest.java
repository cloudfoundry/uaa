package org.cloudfoundry.identity.uaa.logging;

import org.apache.commons.logging.Log;
import org.junit.Before;
import org.junit.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class SanitizedLogFactoryTest {

    Log mockLog;

    @Before
    public void setUp() {
        mockLog = mock(Log.class);
    }

    @Test
    public void testSanitizeDebug() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        log.debug("one\ntwo\tthree\rfour");
        verify(mockLog).debug("one|two|three|four[SANITIZED]");
    }

    @Test
    public void testSanitizeDebugCleanMessage() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        log.debug("one two three four");
        verify(mockLog).debug("one two three four");
    }

    @Test
    public void testSanitizeInfo() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        log.info("one\ntwo\tthree\rfour");
        verify(mockLog).info("one|two|three|four[SANITIZED]");
    }

    @Test
    public void testSanitizeInfoCleanMessage() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        log.info("one two three four");
        verify(mockLog).info("one two three four");
    }

    @Test
    public void testSanitizeWarn() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        log.warn("one\ntwo\tthree\rfour");
        verify(mockLog).warn("one|two|three|four[SANITIZED]");
    }

    @Test
    public void testSanitizeWarnCleanMessage() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        log.warn("one two three four");
        verify(mockLog).warn("one two three four");
    }

}