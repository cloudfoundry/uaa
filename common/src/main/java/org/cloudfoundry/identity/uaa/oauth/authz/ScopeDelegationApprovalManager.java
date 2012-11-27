package org.cloudfoundry.identity.uaa.oauth.authz;

import java.util.Set;

public interface ScopeDelegationApprovalManager {

	public boolean addApproval (ScopeDelegationApproval approval);

	public boolean revokeApprovals (String userId, String clientId);

	public boolean revokeApprovals (String filter);

	public Set<ScopeDelegationApproval> getApprovals (String filter);

	public Set<ScopeDelegationApproval> getApprovals (String userId, String clientId);
}
