package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import static org.cloudfoundry.identity.uaa.provider.IdentityProviderSecretChangeRequest.ChangeMode.DELETE;
import static org.cloudfoundry.identity.uaa.provider.IdentityProviderSecretChangeRequest.ChangeMode.UPDATE;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class IdentityProviderSecretChangeRequest {

    public enum ChangeMode {
        UPDATE,
        DELETE
    }

    private String secret;
    private ChangeMode changeMode;

    public IdentityProviderSecretChangeRequest() {
        changeMode = DELETE;
    }

    public IdentityProviderSecretChangeRequest(String secret) {
        changeMode = UPDATE;
        this.secret = secret;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public ChangeMode getChangeMode() {
        return changeMode;
    }

    public void setChangeMode(ChangeMode changeMode) {
        this.changeMode = changeMode;
    }
}
