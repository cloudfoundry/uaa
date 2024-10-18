/*
 * *****************************************************************************
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

    boolean addApproval(Approval approval, final String zoneId);

    boolean revokeApproval(Approval approval, final String zoneId);

    boolean revokeApprovalsForUser(String userId, final String zoneId);

    boolean revokeApprovalsForClient(String clientId, final String zoneId);

    boolean revokeApprovalsForClientAndUser(String clientId, String userId, final String zoneId);

    List<Approval> getApprovals(String userId, String clientId, final String zoneId);

    List<Approval> getApprovalsForUser(String userId, final String zoneId);

    List<Approval> getApprovalsForClient(String clientId, final String zoneId);
}
