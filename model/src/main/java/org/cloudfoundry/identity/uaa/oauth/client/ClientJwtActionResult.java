package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.resources.ActionResult;

import java.util.List;

/**
 * Response of a change of the jwt configuration of a client. In addition to the status it carries the configuration
 * of the client after the change: the key ids of the jwk set and the federated credentials. A caller can compare it
 * with the state it wants and send the change again.
 */
public class ClientJwtActionResult extends ActionResult {

    private final List<String> kids;
    private final List<ClientJwtCredential> credentials;

    public ClientJwtActionResult(String status, String message, List<String> kids, List<ClientJwtCredential> credentials) {
        super(status, message);
        this.kids = kids;
        this.credentials = credentials;
    }

    @JsonProperty("kids")
    public List<String> getKids() {
        return kids;
    }

    @JsonProperty("jwt_creds")
    public List<ClientJwtCredential> getCredentials() {
        return credentials;
    }
}
