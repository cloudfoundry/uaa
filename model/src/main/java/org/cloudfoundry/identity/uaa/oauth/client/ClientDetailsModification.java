package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientDetailsModification extends BaseClientDetails {

    public static final String ADD = "add";
    public static final String UPDATE = "update";
    public static final String UPDATE_SECRET = "update,secret";
    public static final String DELETE = "delete";
    public static final String SECRET = "secret";
    public static final String NONE = "none";

    @JsonIgnore
    private String action = NONE;

    public ClientDetailsModification() {
    }

    public ClientDetailsModification(ClientDetails prototype) {
        super(prototype);
        if (prototype instanceof BaseClientDetails) {
            BaseClientDetails baseClientDetails = (BaseClientDetails)prototype;
            this.setAdditionalInformation(baseClientDetails.getAdditionalInformation());
            if (baseClientDetails.getAutoApproveScopes()!=null) {
                this.setAutoApproveScopes(baseClientDetails.getAutoApproveScopes());
            }
        }
        if (prototype instanceof ClientDetailsModification) {
            this.action = ((ClientDetailsModification) prototype).getAction();
            this.setApprovalsDeleted(((ClientDetailsModification) prototype).isApprovalsDeleted());
        }
    }

    @JsonGetter("action")
    private String getActionForSerialization() {
        if(action.equals(NONE)) return null;
        return getAction();
    }

    @JsonSetter("action")
    private void setActionWithoutValidation(String action) {
        this.action = action;
    }

    @JsonIgnore
    public String getAction() {
        return action;
    }

    @JsonIgnore
    public void setAction(String action) {
        if (valid(action)) {
            this.action = action;
        } else {
            throw new IllegalArgumentException("Invalid action:"+action);
        }
    }

    @JsonIgnore
    public boolean isApprovalsDeleted() {
        if (getAdditionalInformation().get(ClientConstants.APPROVALS_DELETED)!=null) {
            return Boolean.TRUE.equals(getAdditionalInformation().get(ClientConstants.APPROVALS_DELETED));
        }
        return false;
    }

    @JsonIgnore
    public void setApprovalsDeleted(boolean approvalsDeleted) {
        addAdditionalInformation(ClientConstants.APPROVALS_DELETED, approvalsDeleted);
    }

    @JsonIgnore
    private boolean valid(String action) {
        return (ADD.equals(action)
            ||  UPDATE.equals(action)
            || DELETE.equals(action)
            || UPDATE_SECRET.equals(action)
            || SECRET.equals(action));
    }
}
