package org.cloudfoundry.identity.uaa.approval;

import java.util.List;

public interface ApprovalStore {

  boolean addApproval(Approval approval, final String zoneId);

  boolean revokeApproval(Approval approval, final String zoneId);

  boolean revokeApprovalsForUser(String userId, final String zoneId);

  boolean revokeApprovalsForClient(String clientId, final String zoneId);

  boolean revokeApprovalsForClientAndUser(String clientId, String userId, final String zoneId);

  List<Approval> getApprovals(String userId, String clientId, final String zoneId);

  List<Approval> getApprovalsForUser(String userId, final String zoneId);

  List<Approval> getApprovalsForClient(String clientId, final String zoneId);
}
