package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CommonLoginPolicyTest {
    private CommonLoginPolicy commonLoginPolicy;
    private LockoutPolicyRetriever lockoutPolicyRetriever;
    private UaaAuditService auditService;
    private AuditEventType failureEventType;
    private AuditEventType successEventType;

    @Before
    public void setup() {
        auditService = mock(UaaAuditService.class);
        lockoutPolicyRetriever = mock(LockoutPolicyRetriever.class);
        successEventType = AuditEventType.UserAuthenticationSuccess;
        failureEventType = AuditEventType.UserAuthenticationFailure;

        commonLoginPolicy = new CommonLoginPolicy(auditService, lockoutPolicyRetriever, successEventType, failureEventType);
    }

    @Test
    public void isAllowed_whenLockoutAfterFailuresIsNegative_returnsTrue() {
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(new LockoutPolicy(-1, -1, 300));

        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");

        assertTrue(result.isAllowed());
        assertEquals(0, result.getFailureCount());
    }

    @Test
    public void isAllowed_whenLockoutAfterFailuresIsPositive_returnsFalseIfTooManyFailedRecentAttempts() {
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(new LockoutPolicy(2, 1, 300));
        AuditEvent auditEvent = new AuditEvent(failureEventType, null, null, null, System.currentTimeMillis()+100, null);
        List<AuditEvent> list = Arrays.asList(auditEvent);
        when(auditService.find(eq("principal"), anyLong())).thenReturn(list);

        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");

        assertFalse(result.isAllowed());
        assertEquals(1, result.getFailureCount());
    }

    @Test
    public void isAllowed_whenLockoutAfterFailuresIsPositive_returnsTrueIfNotTooManyFailedRecentAttempts() {
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(new LockoutPolicy(2, 2, 300));
        AuditEvent auditEvent = new AuditEvent(failureEventType, null, null, null, 1L, null);
        List<AuditEvent> list = Arrays.asList(auditEvent);
        when(auditService.find(eq("principal"), anyLong())).thenReturn(list);

        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");

        assertTrue(result.isAllowed());
        assertEquals(1, result.getFailureCount());
    }
}
