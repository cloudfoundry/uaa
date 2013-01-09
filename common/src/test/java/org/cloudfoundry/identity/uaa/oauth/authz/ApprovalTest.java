package org.cloudfoundry.identity.uaa.oauth.authz;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ApprovalTest {

	@Test
	public void testHashCode() throws Exception {
		assertTrue(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).hashCode() == new Approval("u1", "c1", "s1", 500, Approval.ApprovalStatus.DENIED).hashCode());
		assertFalse(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).hashCode() == new Approval("u1", "c2", "s1", 100, Approval.ApprovalStatus.DENIED).hashCode());
		assertFalse(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).hashCode() == new Approval("u1", "c1", "s2", 100, Approval.ApprovalStatus.DENIED).hashCode());
		assertFalse(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).hashCode() == new Approval("u2", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).hashCode());
		assertFalse(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).hashCode() == new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.APPROVED).hashCode());
	}

	@Test
	public void testEquals() throws Exception {
		assertTrue(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).equals(new Approval("u1", "c1", "s1", 500, Approval.ApprovalStatus.DENIED)));
		assertFalse(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).equals(new Approval("u1", "c2", "s1", 100, Approval.ApprovalStatus.DENIED)));
		assertFalse(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).equals(new Approval("u1", "c1", "s2", 100, Approval.ApprovalStatus.DENIED)));
		assertFalse(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).equals(new Approval("u2", "c1", "s1", 100, Approval.ApprovalStatus.DENIED)));
		assertFalse(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED).equals(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.APPROVED)));

		List<Approval> approvals = Arrays.asList(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.APPROVED),
												 new Approval("u1", "c1", "s2", 100, Approval.ApprovalStatus.APPROVED),
												 new Approval("u1", "c1", "s3", 100, Approval.ApprovalStatus.APPROVED),
												 new Approval("u1", "c2", "s1", 100, Approval.ApprovalStatus.APPROVED),
												 new Approval("u1", "c2", "s2", 100, Approval.ApprovalStatus.DENIED)
												);
		assertTrue(approvals.contains(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.APPROVED)));
		assertFalse(approvals.contains(new Approval("u1", "c1", "s1", 100, Approval.ApprovalStatus.DENIED)));
	}

	@Test
	public void testExpiry() {
		int THIRTY_MINTUES = 30 * 60 * 1000;
		assertTrue(new Approval("u1", "c1", "s1", THIRTY_MINTUES, Approval.ApprovalStatus.APPROVED).isCurrentlyActive());
		assertFalse(new Approval("u1", "c1", "s1", -1, Approval.ApprovalStatus.APPROVED).isCurrentlyActive());
	}
}
