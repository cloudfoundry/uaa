package org.cloudfoundry.identity.uaa.audit;


import org.apache.commons.logging.Log;
import org.cloudfoundry.identity.uaa.logging.LogSanitizerUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.util.ReflectionTestUtils;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.ClientAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.ClientAuthenticationSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PasswordChangeFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationSuccess;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = { LoggingAuditServiceTest.ContextConfiguration.class, LoggingAuditService.class })
@TestPropertySource(properties = { "AUDIT_EVENT_TYPES_DEBUG=ClientAuthenticationSuccess,ClientAuthenticationFailure" })
class LoggingAuditServiceTest {

    @Autowired
    private LoggingAuditService loggingAuditService;

    private Log mockLogger;

    @BeforeEach
    void setup() {
        mockLogger = mock(Log.class);
        ReflectionTestUtils.setField(loggingAuditService, "logger", mockLogger);
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

    @Test
    public void log_outputsClientAuthenticationSuccessEventTypeAtDebugLevel() {
        AuditEvent auditEvent = new AuditEvent(ClientAuthenticationSuccess, "principalId", "origin", "data", 100L, "not-used", null, null);

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).debug(stringCaptor.capture());
        assertFalse(stringCaptor.getValue().contains(LogSanitizerUtil.SANITIZED_FLAG));
    }

    @Test
    public void log_outputsClientAuthenticationFailureEventTypeAtDebugLevel() {
        AuditEvent auditEvent = new AuditEvent(ClientAuthenticationFailure, "principalId", "origin", "data", 100L, "not-used", null, null);

        loggingAuditService.log(auditEvent, "not-used");

        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockLogger).debug(stringCaptor.capture());
        assertFalse(stringCaptor.getValue().contains(LogSanitizerUtil.SANITIZED_FLAG));
    }

    @Configuration
    static class ContextConfiguration {

        @Bean
        public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
            return new PropertySourcesPlaceholderConfigurer();
        }
    }
}
