package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import lombok.Data;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class ClientJwtCredential {

    @JsonProperty("sub")
    private String subject;
    @JsonProperty("iss")
    private String issuer;
    @JsonProperty("aud")
    private String audience;

    @JsonCreator
    public ClientJwtCredential(@JsonProperty("sub") String subject, @JsonProperty("iss") String issuer, @JsonProperty("aud") String audience) {
        this.subject = subject;
        this.issuer = issuer;
        this.audience = audience;
        if (!isValid()) {
            throw new IllegalArgumentException("Invalid federated jwt credentials");
        }
    }

    private boolean isValid() {
        return StringUtils.hasText(subject) && StringUtils.hasText(issuer);
    }

    public static List<ClientJwtCredential> parse(String clientJwtCredentials) {
        try {
            return JsonUtils.readValue(clientJwtCredentials, new TypeReference<>() {});
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalArgumentException("Client jwt configuration cannot be parsed", e);
        }
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        ClientJwtCredential that = (ClientJwtCredential) object;
        return subject.equals(that.subject) &&
               issuer.equals(that.issuer) &&
               Objects.equals(audience, that.audience);
    }

    @Override
    public int hashCode() {
        int result = subject.hashCode();
        result = 31 * result + issuer.hashCode();
        result = 31 * result + (audience != null ? audience.hashCode() : 0);
        return result;
    }
}
