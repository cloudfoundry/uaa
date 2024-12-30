package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import lombok.Builder;
import lombok.Data;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@Builder(toBuilder = true)
@Data
public class ClientJwtCredential {

    @JsonProperty("sub")
    private String subject;
    @JsonProperty("iss")
    private String issuer;
    @JsonProperty("aud")
    private String audience;

    public ClientJwtCredential() {
    }

    public ClientJwtCredential(String subject, String issuer, String audience) {
        this.subject = subject;
        this.issuer = issuer;
        this.audience = audience;
    }

    @JsonIgnore
    public boolean isValid() {
        return subject != null && issuer != null && subject.length() > 0 && issuer.length() > 0;
    }

    @JsonIgnore
    public static List<ClientJwtCredential> parse(String clientJwtCredentials) {
        try {
            return JsonUtils.readValue(clientJwtCredentials, new TypeReference<>() {});
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalArgumentException("Client jwt configuration cannot be parsed", e);
        }
    }

}
