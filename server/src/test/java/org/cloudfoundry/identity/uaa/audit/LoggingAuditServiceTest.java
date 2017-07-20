package org.cloudfoundry.identity.uaa.audit;


import org.apache.commons.logging.Log;
import org.cloudfoundry.identity.uaa.logging.LogSanitizerUtil;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PasswordChangeFailure;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class LoggingAuditServiceTest {

    private LoggingAuditService loggingAuditService;
    private Log mockLogger;

    @Before
    public void setup() {
        loggingAuditService = new LoggingAuditService();
        mockLogger = mock(Log.class);
        loggingAuditService.setLogger(mockLogger);
    }

    @Test
    public void log_sanitizesMaliciousInput() {
        AuditEvent auditEvent = new AuditEvent(PasswordChangeFailure, "principalId", "origin", "data", 100L, "malicious-zone\r\n\t");

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).info(stringCaptor.capture());
        assertFalse(stringCaptor.getValue().contains("\r"));
        assertFalse(stringCaptor.getValue().contains("\n"));
        assertFalse(stringCaptor.getValue().contains("\t"));
        assertTrue(stringCaptor.getValue().contains(LogSanitizerUtil.SANITIZED_FLAG));
    }

    @Test
    public void log_doesNotModifyNonMaliciousInput() {
        AuditEvent auditEvent = new AuditEvent(PasswordChangeFailure, "principalId", "origin", "data", 100L, "safe-zone");

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).info(stringCaptor.capture());
        assertFalse(stringCaptor.getValue().contains(LogSanitizerUtil.SANITIZED_FLAG));
    }
}
