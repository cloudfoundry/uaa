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


import com.fasterxml.jackson.annotation.JsonIgnore;

public class DescribedApproval extends Approval {
    private String description;

    public DescribedApproval() {
    }

    public DescribedApproval(Approval approval) {
        this
                .setLastUpdatedAt(approval.getLastUpdatedAt())
                .setUserId(approval.getUserId())
                .setStatus(approval.getStatus())
                .setExpiresAt(approval.getExpiresAt())
                .setScope(approval.getScope())
                .setClientId(approval.getClientId());
    }

    @JsonIgnore
    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

}
