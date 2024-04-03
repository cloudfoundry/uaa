package org.cloudfoundry.identity.uaa.logging;

import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.apache.commons.lang3.RandomStringUtils;

public class SanitizedLogFactoryTest {

    private final String dirtyMessage = "one\ntwo\tthree\rfour";
    private final String sanitizedMsg = "one|two|three|four[SANITIZED]";
    private final String cleanMessage = "one two three four";

    Logger mockLog;
    SanitizedLogFactory.SanitizedLog log;
    Exception ex;

    @Before
    public void setUp() {
        mockLog = mock(Logger.class);
        log = new SanitizedLogFactory.SanitizedLog(mockLog);
        ex = new Exception(RandomStringUtils.randomAlphanumeric(8));
    }

    @Test
    public void testInit() {
        Assert.assertNotNull(SanitizedLogFactory.getLog(SanitizedLogFactoryTest.class));
    }

    @Test
    public void testSanitizeInfo() {
        when(mockLog.isInfoEnabled()).thenReturn(true);
        log.info(dirtyMessage);
        verify(mockLog).info(sanitizedMsg);
        log.info(dirtyMessage, ex);
        verify(mockLog).info(sanitizedMsg, ex);
    }

    @Test
    public void testSanitizeInfoCleanMessage() {
        when(mockLog.isInfoEnabled()).thenReturn(true);
        log.info(cleanMessage);
        verify(mockLog).info(cleanMessage);
        log.info(cleanMessage, ex);
        verify(mockLog).info(cleanMessage, ex);
    }

    @Test
    public void testSanitizeDebug() {
        when(mockLog.isDebugEnabled()).thenReturn(true);
        log.debug(dirtyMessage);
        verify(mockLog).debug(sanitizedMsg);
        log.debug(dirtyMessage, ex);
        verify(mockLog).debug(sanitizedMsg, ex);
    }

    @Test
    public void testSanitizeDebugCleanMessage() {
        when(mockLog.isDebugEnabled()).thenReturn(true);
        log.debug(cleanMessage);
        verify(mockLog).debug(cleanMessage);
        log.debug(cleanMessage, ex);
        verify(mockLog).debug(cleanMessage, ex);
    }

    @Test
    public void testSanitizeDebugCleanMessageNotEnabled() {
        when(mockLog.isDebugEnabled()).thenReturn(false);
        log.debug(cleanMessage);
        verify(mockLog, never()).debug(cleanMessage);
        log.debug(cleanMessage, ex);
        verify(mockLog, never()).debug(cleanMessage, ex);
        Assert.assertFalse(log.isDebugEnabled());
    }


    @Test
    public void testSanitizeWarn() {
        when(mockLog.isWarnEnabled()).thenReturn(true);
        log.warn(dirtyMessage);
        verify(mockLog).warn(sanitizedMsg);
        log.warn(dirtyMessage, ex);
        verify(mockLog).warn(sanitizedMsg, ex);
    }

    @Test
    public void testSanitizeWarnCleanMessage() {
        when(mockLog.isWarnEnabled()).thenReturn(true);
        log.warn(cleanMessage);
        verify(mockLog).warn(cleanMessage);
        log.warn(cleanMessage, ex);
        verify(mockLog).warn(cleanMessage, ex);
    }

    @Test
    public void testSanitizeWarnCleanMessageNotEnabled() {
        when(mockLog.isWarnEnabled()).thenReturn(false);
        log.warn(cleanMessage);
        verify(mockLog, never()).warn(cleanMessage);
        log.warn(cleanMessage, ex);
        verify(mockLog, never()).warn(cleanMessage, ex);
    }

    @Test
    public void testSanitizeError() {
        when(mockLog.isErrorEnabled()).thenReturn(true);
        log.error(dirtyMessage);
        verify(mockLog).error(sanitizedMsg);
        log.error(dirtyMessage, ex);
        verify(mockLog).error(sanitizedMsg, ex);
    }

    @Test
    public void testSanitizeErrorCleanMessage() {
        when(mockLog.isErrorEnabled()).thenReturn(true);
        log.error(cleanMessage);
        verify(mockLog).error(cleanMessage);
        log.error(cleanMessage, ex);
        verify(mockLog).error(cleanMessage, ex);
    }

    @Test
    public void testSanitizeTrace() {
        when(mockLog.isTraceEnabled()).thenReturn(true);
        log.trace(dirtyMessage);
        verify(mockLog).trace(sanitizedMsg);
        log.trace(dirtyMessage, ex);
        verify(mockLog).trace(sanitizedMsg, ex);
    }

    @Test
    public void testSanitizeTraceCleanMessage() {
        when(mockLog.isTraceEnabled()).thenReturn(true);
        log.trace(cleanMessage);
        verify(mockLog).trace(cleanMessage);
        log.trace(cleanMessage, ex);
        verify(mockLog).trace(cleanMessage, ex);
    }

    @Test
    public void testSanitizeTraceCleanMessageWhenNotEnabled() {
        when(mockLog.isTraceEnabled()).thenReturn(false);
        log.trace(cleanMessage);
        verify(mockLog, never()).trace(cleanMessage);
        log.trace(cleanMessage, ex);
        verify(mockLog, never()).trace(cleanMessage, ex);
    }
}
