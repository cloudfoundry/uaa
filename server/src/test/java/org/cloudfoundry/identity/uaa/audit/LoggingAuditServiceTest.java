package org.cloudfoundry.identity.uaa.audit;


import org.cloudfoundry.identity.uaa.logging.LogSanitizerUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.Logger;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PasswordChangeFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationSuccess;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class LoggingAuditServiceTest {

    private LoggingAuditService loggingAuditService;
    private Logger mockLogger;

    @BeforeEach
    void setup() {
        loggingAuditService = new LoggingAuditService();
        mockLogger = mock(Logger.class);
        loggingAuditService.setLogger(mockLogger);
    }

    @Test
    void log_format_whenThereIsAnAuthType() {
        AuditEvent auditEvent = new AuditEvent(PasswordChangeFailure, "thePrincipalId", "theOrigin", "theData", 42L, "theZoneId", "theAuthType", "theDescription");

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).info(stringCaptor.capture());
        String logMessage = stringCaptor.getValue();
        assertThat(logMessage, is("PasswordChangeFailure ('theData'): principal=thePrincipalId, origin=[theOrigin], identityZoneId=[theZoneId], authenticationType=[theAuthType]"));
    }

    @Test
    void log_format_whenAuthTypeIsNull() {
        AuditEvent auditEvent = new AuditEvent(PasswordChangeFailure, "thePrincipalId", "theOrigin", "theData", 42L, "theZoneId", null, "theDescription");

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).info(stringCaptor.capture());
        String logMessage = stringCaptor.getValue();
        assertThat(logMessage, is("PasswordChangeFailure ('theData'): principal=thePrincipalId, origin=[theOrigin], identityZoneId=[theZoneId]"));
    }

    @Test
    void log_sanitizesMaliciousInput() {
        AuditEvent auditEvent = new AuditEvent(UserAuthenticationSuccess, "principalId", "origin", "data", 100L, "malicious-zone\r\n\t", null, null);

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).info(stringCaptor.capture());
        assertFalse(stringCaptor.getValue().contains("\r"));
        assertFalse(stringCaptor.getValue().contains("\n"));
        assertFalse(stringCaptor.getValue().contains("\t"));
        assertTrue(stringCaptor.getValue().contains(LogSanitizerUtil.SANITIZED_FLAG));
    }

    @Test
    void log_doesNotModifyNonMaliciousInput() {
        AuditEvent auditEvent = new AuditEvent(UserAuthenticationSuccess, "principalId", "origin", "data", 100L, "safe-zone", null, null);

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).info(stringCaptor.capture());
        assertFalse(stringCaptor.getValue().contains(LogSanitizerUtil.SANITIZED_FLAG));
    }
}
