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
package org.cloudfoundry.identity.uaa.approval;

import java.util.List;

public interface ApprovalStore {

    public boolean addApproval(Approval approval);

    public boolean revokeApproval(Approval approval);

    public boolean revokeApprovalsForUser(String userId);

    public boolean revokeApprovalsForClient(String clientId);

    public boolean revokeApprovalsForClientAndUser(String clientId, String userId);

    public List<Approval> getApprovals(String userId, String clientId);

    public List<Approval> getApprovalsForUser(String userId);

    public List<Approval> getApprovalsForClient(String clientId);
}
