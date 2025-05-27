package org.cloudfoundry.identity.uaa.logging;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SanitizedLogFactoryTest {

    private final String dirtyMessage = "one\ntwo\tthree\rfour";
    private final String sanitizedMsg = "one|two|three|four[SANITIZED]";
    private final String cleanMessage = "one two three four";

    Logger mockLog;
    SanitizedLogFactory.SanitizedLog log;
    Exception ex;

    @BeforeEach
    void setUp() {
        mockLog = mock(Logger.class);
        log = new SanitizedLogFactory.SanitizedLog(mockLog);
        ex = new Exception(RandomStringUtils.randomAlphanumeric(8));
    }

    @Test
    void init() {
        assertThat(SanitizedLogFactory.getLog(SanitizedLogFactoryTest.class)).isNotNull();
    }

    @Test
    void sanitizeInfo() {
        when(mockLog.isInfoEnabled()).thenReturn(true);
        log.info(dirtyMessage);
        verify(mockLog).info(sanitizedMsg);
        log.info(dirtyMessage, ex);
        verify(mockLog).info(sanitizedMsg, ex);
    }

    @Test
    void sanitizeInfoCleanMessage() {
        when(mockLog.isInfoEnabled()).thenReturn(true);
        log.info(cleanMessage);
        verify(mockLog).info(cleanMessage);
        log.info(cleanMessage, ex);
        verify(mockLog).info(cleanMessage, ex);
    }

    @Test
    void sanitizeDebug() {
        when(mockLog.isDebugEnabled()).thenReturn(true);
        log.debug(dirtyMessage);
        verify(mockLog).debug(sanitizedMsg);
        log.debug(dirtyMessage, true);
        verify(mockLog).debug(sanitizedMsg);
        log.debug(dirtyMessage, ex);
        verify(mockLog).debug(sanitizedMsg, ex);
    }

    @Test
    void sanitizeDebugCleanMessage() {
        when(mockLog.isDebugEnabled()).thenReturn(true);
        log.debug(cleanMessage);
        verify(mockLog).debug(cleanMessage);
        log.debug(cleanMessage, ex);
        verify(mockLog).debug(cleanMessage, ex);
    }

    @Test
    void sanitizeDebugCleanMessageNotEnabled() {
        when(mockLog.isDebugEnabled()).thenReturn(false);
        log.debug(cleanMessage);
        verify(mockLog, never()).debug(cleanMessage);
        log.debug(cleanMessage, ex);
        verify(mockLog, never()).debug(cleanMessage, ex);
        assertThat(log.isDebugEnabled()).isFalse();
    }

    @Test
    void sanitizeWarn() {
        when(mockLog.isWarnEnabled()).thenReturn(true);
        log.warn(dirtyMessage);
        verify(mockLog).warn(sanitizedMsg);
        log.warn(dirtyMessage, ex);
        verify(mockLog).warn(sanitizedMsg, ex);
    }

    @Test
    void sanitizeWarnCleanMessage() {
        when(mockLog.isWarnEnabled()).thenReturn(true);
        log.warn(cleanMessage);
        verify(mockLog).warn(cleanMessage);
        log.warn(cleanMessage, ex);
        verify(mockLog).warn(cleanMessage, ex);
    }

    @Test
    void sanitizeWarnCleanMessageNotEnabled() {
        when(mockLog.isWarnEnabled()).thenReturn(false);
        log.warn(cleanMessage);
        verify(mockLog, never()).warn(cleanMessage);
        log.warn(cleanMessage, ex);
        verify(mockLog, never()).warn(cleanMessage, ex);
    }

    @Test
    void sanitizeError() {
        when(mockLog.isErrorEnabled()).thenReturn(true);
        log.error(dirtyMessage);
        verify(mockLog).error(sanitizedMsg);
        log.error(dirtyMessage, ex);
        verify(mockLog).error(sanitizedMsg, ex);
    }

    @Test
    void sanitizeErrorCleanMessage() {
        when(mockLog.isErrorEnabled()).thenReturn(true);
        log.error(cleanMessage);
        verify(mockLog).error(cleanMessage);
        log.error(cleanMessage, ex);
        verify(mockLog).error(cleanMessage, ex);
    }

    @Test
    void sanitizeTrace() {
        when(mockLog.isTraceEnabled()).thenReturn(true);
        log.trace(dirtyMessage);
        verify(mockLog).trace(sanitizedMsg);
        log.trace(dirtyMessage, ex);
        verify(mockLog).trace(sanitizedMsg, ex);
    }

    @Test
    void sanitizeTraceCleanMessage() {
        when(mockLog.isTraceEnabled()).thenReturn(true);
        log.trace(cleanMessage);
        verify(mockLog).trace(cleanMessage);
        log.trace(cleanMessage, ex);
        verify(mockLog).trace(cleanMessage, ex);
    }

    @Test
    void sanitizeTraceCleanMessageWhenNotEnabled() {
        when(mockLog.isTraceEnabled()).thenReturn(false);
        log.trace(cleanMessage);
        verify(mockLog, never()).trace(cleanMessage);
        log.trace(cleanMessage, ex);
        verify(mockLog, never()).trace(cleanMessage, ex);
    }
}
