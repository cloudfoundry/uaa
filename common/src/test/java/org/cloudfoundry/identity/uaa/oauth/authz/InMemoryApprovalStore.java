package org.cloudfoundry.identity.uaa.oauth.authz;

import java.util.ArrayList;
import java.util.List;

public class InMemoryApprovalStore implements ApprovalStore {

	private List<Approval> approvalStore = new ArrayList<Approval>();

	@Override
	public boolean addApproval(Approval approval) {
		return approvalStore.add(approval);
	}

	@Override
	public boolean revokeApproval(Approval approval) {
		for(Approval a : approvalStore) {
			if (a == approval) {
				return approvalStore.remove(approval);
			}
		}
		return false;
	}

	@Override
	public boolean revokeApprovals(String filter) {
		return false;
	}

	@Override
	public List<Approval> getApprovals(String filter) {
		return null;
	}

	@Override
	public List<Approval> getApprovals(String userName, String clientId) {
		List<Approval> returnList = new ArrayList<Approval>();
		for(Approval a : approvalStore) {
			if (a.getUserName().equals(userName) && a.getClientId().equals(clientId)) {
				returnList.add(a);
			}
		}

		return returnList;
	}

}
