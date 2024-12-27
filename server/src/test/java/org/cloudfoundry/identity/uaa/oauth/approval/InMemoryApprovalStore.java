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
package org.cloudfoundry.identity.uaa.oauth.approval;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;

import java.util.ArrayList;
import java.util.List;

public class InMemoryApprovalStore implements ApprovalStore {

    private final ArrayList<Approval> store = new ArrayList<>();

    @Override
    public boolean addApproval(Approval approval, final String zoneId) {
        return store.add(approval);
    }

    @Override
    public boolean revokeApproval(Approval approval, final String zoneId) {
        for (Approval a : store) {
            if (a.equals(approval)) {
                store.remove(a);
                return true;
            }
        }
        return false;
    }

    @Override
    public List<Approval> getApprovals(String userName, String clientId, final String zoneId) {
        ArrayList<Approval> returnList = new ArrayList<>();

        for (Approval a : store) {
            if (a.getUserId().equals(userName) && a.getClientId().equals(clientId)) {
                returnList.add(a);
            }
        }
        return returnList;
    }

    @Override
    public boolean revokeApprovalsForUser(String userId, final String zoneId) {
        return store.removeIf(approval -> userId.equals(approval.getUserId()));
    }

    @Override
    public boolean revokeApprovalsForClient(String clientId, final String zoneId) {
        return store.removeIf(approval -> clientId.equals(approval.getClientId()));
    }

    @Override
    public boolean revokeApprovalsForClientAndUser(String clientId, String userId, final String zoneId) {
        return store.removeIf(
                approval ->
                        clientId.equals(approval.getClientId()) &&
                                userId.equals(approval.getUserId())
        );
    }

    @Override
    public List<Approval> getApprovalsForUser(String userId, final String zoneId) {
        return store.stream()
                .filter(approval -> userId.equals(approval.getUserId()))
                .toList();
    }

    @Override
    public List<Approval> getApprovalsForClient(String clientId, final String zoneId) {
        return store.stream()
                .filter(approval -> clientId.equals(approval.getClientId()))
                .toList();
    }
}
