package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class CommonLoginPolicyTest {
    private CommonLoginPolicy commonLoginPolicy;
    private LockoutPolicyRetriever lockoutPolicyRetriever;
    private TimeService timeService;
    private UaaAuditService auditService;
    private AuditEventType failureEventType;
    private AuditEventType successEventType;
    private final boolean enabled = true;

    @BeforeEach
    void setup() {
        auditService = mock(UaaAuditService.class);
        timeService = mock(TimeService.class);
        lockoutPolicyRetriever = mock(LockoutPolicyRetriever.class);
        successEventType = AuditEventType.UserAuthenticationSuccess;
        failureEventType = AuditEventType.UserAuthenticationFailure;

        commonLoginPolicy = new CommonLoginPolicy(auditService, lockoutPolicyRetriever, successEventType, failureEventType, timeService, enabled);
    }

    @Test
    void is_disabled() {
        commonLoginPolicy = spy(new CommonLoginPolicy(auditService, lockoutPolicyRetriever, successEventType, failureEventType, timeService, false));
        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");
        assertThat(result.isAllowed()).isTrue();
        assertThat(result.getFailureCount()).isZero();
        verifyNoInteractions(lockoutPolicyRetriever);
        verifyNoInteractions(timeService);
        verifyNoInteractions(auditService);
    }

    @Test
    void isAllowed_whenLockoutAfterFailuresIsNegative_returnsTrue() {
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(new LockoutPolicy(-1, -1, 300));

        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");

        assertThat(result.isAllowed()).isTrue();
        assertThat(result.getFailureCount()).isZero();
    }

    @Test
    void isAllowed_whenLockoutAfterFailuresIsPositive_returnsFalseIfTooManyUnsuccessfulRecentAttempts() {
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(new LockoutPolicy(2, 1, 300));
        AuditEvent auditEvent = new AuditEvent(failureEventType, null, null, null, 1L, null, null, null);
        List<AuditEvent> list = Collections.singletonList(auditEvent);
        String zoneId = IdentityZoneHolder.get().getId();
        when(auditService.find(eq("principal"), anyLong(), eq(zoneId))).thenReturn(list);

        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");

        assertThat(result.isAllowed()).isFalse();
        assertThat(result.getFailureCount()).isOne();
    }

    @Test
    void isAllowed_whenLockoutAfterFailuresIsPositive_returnsTrueIfNotTooManyUnsuccessfulRecentAttempts() {
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(new LockoutPolicy(2, 2, 300));
        AuditEvent auditEvent = new AuditEvent(failureEventType, null, null, null, 1L, null, null, null);
        List<AuditEvent> list = Collections.singletonList(auditEvent);
        String zoneId = IdentityZoneHolder.get().getId();
        when(auditService.find(eq("principal"), anyLong(), eq(zoneId))).thenReturn(list);

        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");

        assertThat(result.isAllowed()).isTrue();
        assertThat(result.getFailureCount()).isOne();
    }
}
