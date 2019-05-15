/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.approval;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.junit.Test;

public class ApprovalTests {

    @Test
    public void testHashCode() throws Exception {
        assertTrue(new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).hashCode() == new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(500))
            .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertFalse(new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).hashCode() == new Approval()
            .setUserId("u1")
            .setClientId("c2")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertFalse(new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).hashCode() == new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s2")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertFalse(new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).hashCode() == new Approval()
            .setUserId("u2")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertFalse(new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).hashCode() == new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.APPROVED).hashCode());
    }

    @Test
    public void testEquals() throws Exception {
        assertTrue(new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).equals(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(500))
                .setStatus(Approval.ApprovalStatus.DENIED)));
        assertFalse(new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).equals(new Approval()
                .setUserId("u1")
                .setClientId("c2")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED)));
        assertFalse(new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).equals(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s2")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED)));
        assertFalse(new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).equals(new Approval()
                .setUserId("u2")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED)));
        assertFalse(new Approval()
            .setUserId("u1")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(100))
            .setStatus(Approval.ApprovalStatus.DENIED).equals(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.APPROVED)));

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
