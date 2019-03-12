package org.cloudfoundry.identity.uaa.audit;


import org.apache.commons.logging.Log;
import org.cloudfoundry.identity.uaa.logging.LogSanitizerUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.util.ReflectionTestUtils;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.ClientAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.ClientAuthenticationSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PasswordChangeFailure;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { LoggingAuditServiceTest.ContextConfiguration.class, LoggingAuditService.class })
@TestPropertySource(properties = { "AUDIT_EVENT_TYPES_DEBUG=ClientAuthenticationSuccess,ClientAuthenticationFailure" })
public class LoggingAuditServiceTest {

    @Autowired
    private LoggingAuditService loggingAuditService;

    private Log mockLogger;

    @Before
    public void setup() {
        mockLogger = mock(Log.class);
        ReflectionTestUtils.setField(loggingAuditService, "logger", mockLogger);
    }

    @Test
    public void log_sanitizesMaliciousInput() {
        AuditEvent auditEvent = new AuditEvent(PasswordChangeFailure, "principalId", "origin", "data", 100L, "malicious-zone\r\n\t", null, null);

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
        AuditEvent auditEvent = new AuditEvent(PasswordChangeFailure, "principalId", "origin", "data", 100L, "safe-zone", null, null);

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
