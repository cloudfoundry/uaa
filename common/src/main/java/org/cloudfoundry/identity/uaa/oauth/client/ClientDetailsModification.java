package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
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

    @JsonProperty("action")
    private String action = NONE;

    public ClientDetailsModification() {
    }

    public ClientDetailsModification(String clientId, String resourceIds, String scopes, String grantTypes, String authorities, String redirectUris) {
        super(clientId, resourceIds, scopes, grantTypes, authorities, redirectUris);
    }

    public ClientDetailsModification(String clientId, String resourceIds, String scopes, String grantTypes, String authorities) {
        super(clientId, resourceIds, scopes, grantTypes, authorities);
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
            this.setAction(((ClientDetailsModification) prototype).getAction());
            this.setApprovalsDeleted(((ClientDetailsModification) prototype).isApprovalsDeleted());
        }
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
            || SECRET.equals(SECRET));
    }
}
