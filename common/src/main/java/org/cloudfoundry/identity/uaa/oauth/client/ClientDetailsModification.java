package org.cloudfoundry.identity.uaa.oauth.client;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;

public class ClientDetailsModification extends BaseClientDetails {

    public static final String ADD = "add";
    public static final String UPDATE = "update";
    public static final String DELETE = "delete";
    public static final String NONE = "none";

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
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        if (valid(action)) {
            this.action = action;
        } else {
            throw new IllegalArgumentException("Invalid action:"+action);
        }
    }

    @JsonIgnore
    private boolean valid(String action) {
        return (ADD.equals(action)
            ||  UPDATE.equals(action)
            || DELETE.equals(action));
    }
}
