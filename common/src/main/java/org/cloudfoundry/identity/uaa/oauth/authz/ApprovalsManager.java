package org.cloudfoundry.identity.uaa.oauth.authz;

import java.util.List;

public interface ApprovalsManager {

	public boolean addApproval (Approval approval);

	public boolean revokeApproval (Approval approval);

	public boolean revokeApprovals (String filter);

	public List<Approval> getApprovals (String filter);

	public List<Approval> getApprovals (String userName, String clientId);
}
