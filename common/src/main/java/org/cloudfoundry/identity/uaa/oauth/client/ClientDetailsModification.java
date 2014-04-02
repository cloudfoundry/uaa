package org.cloudfoundry.identity.uaa.oauth.client;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_DEFAULT)
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
    @JsonProperty("approvals_deleted")
    private boolean approvalsDeleted = false;

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
            this.setAdditionalInformation(((BaseClientDetails)prototype).getAdditionalInformation());
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
        return approvalsDeleted;
    }

    @JsonIgnore
    public void setApprovalsDeleted(boolean approvalsDeleted) {
        this.approvalsDeleted = approvalsDeleted;
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
