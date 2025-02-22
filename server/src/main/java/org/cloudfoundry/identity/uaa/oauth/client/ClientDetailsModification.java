package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

import java.util.List;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientDetailsModification extends UaaClientDetails {

    public static final String ADD = "add";
    public static final String UPDATE = "update";
    public static final String UPDATE_SECRET = "update,secret";
    public static final String DELETE = "delete";
    public static final String SECRET = "secret";
    public static final String NONE = "none";

    @JsonIgnore
    private String action = NONE;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("jwks")
    private transient JsonWebKeySet<JsonWebKey> jwkSet;

    @JsonProperty("jwt_creds")
    private transient List<ClientJwtCredential> clientJwtCredentials;

    public ClientDetailsModification() {
    }

    public ClientDetailsModification(ClientDetails prototype) {
        super(prototype);
        if (prototype instanceof UaaClientDetails baseClientDetails) {
            this.setAdditionalInformation(baseClientDetails.getAdditionalInformation());
            if (baseClientDetails.getAutoApproveScopes() != null) {
                this.setAutoApproveScopes(baseClientDetails.getAutoApproveScopes());
            }
            if (baseClientDetails.getClientJwtConfig() instanceof String ) {
                ClientJwtConfiguration clientJwtConfiguration = ClientJwtConfiguration.readValue(baseClientDetails);
                this.setJwksUri(clientJwtConfiguration.getJwksUri());
                this.setJwkSet(clientJwtConfiguration.getJwkSet());
                this.setClientJwtCredentials(clientJwtConfiguration.getClientJwtCredentials());
            }
        }
        if (prototype instanceof ClientDetailsModification modification) {
            this.action = modification.getAction();
            this.setApprovalsDeleted(modification.isApprovalsDeleted());
        }
    }

    @JsonGetter("action")
    private String getActionForSerialization() {
        if (action.equals(NONE)) {
            return null;
        }
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
            throw new IllegalArgumentException("Invalid action:" + action);
        }
    }

    @JsonIgnore
    public boolean isApprovalsDeleted() {
        if (getAdditionalInformation().get(ClientConstants.APPROVALS_DELETED) != null) {
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
        return ADD.equals(action)
                || UPDATE.equals(action)
                || DELETE.equals(action)
                || UPDATE_SECRET.equals(action)
                || SECRET.equals(action);
    }

    public String getJwksUri() {
        return this.jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public JsonWebKeySet<JsonWebKey> getJwkSet() {
        return this.jwkSet;
    }

    public void setJwkSet(final JsonWebKeySet<JsonWebKey> jwkSet) {
        this.jwkSet = jwkSet;
    }

    public List<ClientJwtCredential> getClientJwtCredentials() {
        return this.clientJwtCredentials;
    }

    public void setClientJwtCredentials(final List<ClientJwtCredential> clientJwtCredentials) {
        this.clientJwtCredentials = clientJwtCredentials;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        if (!super.equals(other)) {
            return false;
        }
        ClientDetailsModification that = (ClientDetailsModification) other;
        if (!Objects.equals(jwksUri, that.jwksUri)) {
            return false;
        }
        if (!Objects.equals(jwkSet, that.jwkSet)) {
            return false;
        }
        if (!Objects.equals(clientJwtCredentials, that.clientJwtCredentials)) {
            return false;
        }
        return Objects.equals(action, that.action);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + (action != null ? action.hashCode() : 0);
        result = prime * result + (jwksUri == null ? 0 : jwksUri.hashCode());
        result = prime * result + (jwkSet == null ? 0 : jwkSet.hashCode());
        result = prime * result + (clientJwtCredentials == null ? 0 : clientJwtCredentials.hashCode());
        return result;
    }
}
