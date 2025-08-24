package org.cloudfoundry.identity.uaa.audit;

import org.cloudfoundry.identity.uaa.logging.LogSanitizerUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PasswordChangeFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationSuccess;
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
        assertThat(logMessage).isEqualTo("PasswordChangeFailure ('theData'): principal=thePrincipalId, origin=[theOrigin], identityZoneId=[theZoneId], authenticationType=[theAuthType], detailedDescription=[theDescription]");
    }

    @Test
    void log_format_whenAuthTypeIsNull() {
        AuditEvent auditEvent = new AuditEvent(PasswordChangeFailure, "thePrincipalId", "theOrigin", "theData", 42L, "theZoneId", null, "theDescription");

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).info(stringCaptor.capture());
        String logMessage = stringCaptor.getValue();
        assertThat(logMessage).isEqualTo("PasswordChangeFailure ('theData'): principal=thePrincipalId, origin=[theOrigin], identityZoneId=[theZoneId], detailedDescription=[theDescription]");
    }

    @Test
    void log_sanitizesMaliciousInput() {
        AuditEvent auditEvent = new AuditEvent(UserAuthenticationSuccess, "principalId", "origin", "data", 100L, "malicious-zone\r\n\t", null, null);

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).info(stringCaptor.capture());
        assertThat(stringCaptor.getValue()).doesNotContain("\r")
                .doesNotContain("\n")
                .doesNotContain("\t")
                .contains(LogSanitizerUtil.SANITIZED_FLAG);
    }

    @Test
    void log_doesNotModifyNonMaliciousInput() {
        AuditEvent auditEvent = new AuditEvent(UserAuthenticationSuccess, "principalId", "origin", "data", 100L, "safe-zone", null, null);

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).info(stringCaptor.capture());
        assertThat(stringCaptor.getValue()).doesNotContain(LogSanitizerUtil.SANITIZED_FLAG);
    }
}
