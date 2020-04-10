
package org.cloudfoundry.identity.uaa.approval;


import com.fasterxml.jackson.annotation.JsonIgnore;
import org.cloudfoundry.identity.uaa.approval.Approval;

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
