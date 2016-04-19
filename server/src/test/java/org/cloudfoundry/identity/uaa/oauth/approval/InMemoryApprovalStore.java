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

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;

import java.util.ArrayList;
import java.util.List;

/**
 * 
 * @author Joel D'sa
 * 
 */
public class InMemoryApprovalStore implements ApprovalStore {

    private ArrayList<Approval> store = new ArrayList<Approval>();

    @Override
    public boolean addApproval(Approval approval) {
        return store.add(approval);
    }

    @Override
    public boolean revokeApproval(Approval approval) {
        for (Approval a : store) {
            if (a.equals(approval)) {
                store.remove(a);
                return true;
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
        ArrayList<Approval> returnList = new ArrayList<Approval>();

        for (Approval a : store) {
            if (a.getUserId().equals(userName) && a.getClientId().equals(clientId)) {
                returnList.add(a);
            }
        }
        return returnList;
    }

}
