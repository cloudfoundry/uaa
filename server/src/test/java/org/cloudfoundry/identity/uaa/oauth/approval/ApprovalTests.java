package org.cloudfoundry.identity.uaa.oauth.approval;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.junit.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.*;

public class ApprovalTests {

    @Test
    public void testHashCode() {
        assertEquals(
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED).hashCode(),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(500))
                        .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertNotEquals(
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED).hashCode(),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c2")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertNotEquals(
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED).hashCode(),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s2")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertNotEquals(
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED).hashCode(),
                new Approval()
                        .setUserId("u2")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertNotEquals(
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED).hashCode(),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.APPROVED).hashCode());
    }

    @Test
    public void testEquals() {
        assertEquals(new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(500))
                        .setStatus(Approval.ApprovalStatus.DENIED));
        assertNotEquals(
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c2")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED));
        assertNotEquals(
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s2")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED));
        assertNotEquals(
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED),
                new Approval()
                        .setUserId("u2")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED));
        assertNotEquals(
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.APPROVED));

        List<Approval> approvals = Arrays.asList(new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.APPROVED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s2")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.APPROVED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s3")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.APPROVED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c2")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.APPROVED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c2")
                        .setScope("s2")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED)
        );
        assertTrue(approvals.contains(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.APPROVED)));
        assertFalse(approvals.contains(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED)));
    }

    @Test
    public void testExpiry() {
        int THIRTY_MINTUES = 30 * 60 * 1000;
        assertTrue(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(THIRTY_MINTUES))
                .setStatus(Approval.ApprovalStatus.APPROVED).isActiveAsOf(new Date()));
        int expiresIn = -1;
        assertFalse(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(expiresIn))
                .setStatus(Approval.ApprovalStatus.APPROVED).isActiveAsOf(new Date()));
    }
}
