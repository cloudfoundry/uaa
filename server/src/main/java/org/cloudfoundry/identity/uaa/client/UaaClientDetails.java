package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
@JsonIgnoreProperties(ignoreUnknown = true)
public class UaaClientDetails extends BaseClientDetails {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    @JsonProperty("client_jwt_config")
    private String clientJwtConfig;

    public UaaClientDetails() {
    }

    UaaClientDetails(ClientDetails prototype) {
        super(prototype);
        setAdditionalInformation(prototype.getAdditionalInformation());
    }

    public UaaClientDetails(String clientId, String resourceIds,
        String scopes, String grantTypes, String authorities, String redirectUris) {
        super(clientId, resourceIds, scopes, grantTypes, authorities, redirectUris);
        this.clientJwtConfig = clientJwtConfig;
    }

    @Override
    public void setScope(Collection<String> scope) {
        Set<String> sanitized = scope.stream()
                .flatMap(s -> Arrays.stream(s.split(",")))
                .collect(Collectors.toSet());
        super.setScope(sanitized);
    }

    public String getClientJwtConfig() {
        return clientJwtConfig;
    }

    public void setClientJwtConfig(String clientJwtConfig) {
        this.clientJwtConfig = clientJwtConfig;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (o instanceof UaaClientDetails) {
            UaaClientDetails uaaClientDetails = (UaaClientDetails) o;
            return Objects.equals(clientJwtConfig, uaaClientDetails.clientJwtConfig);
        }
        return false;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();

        result = 31 * result + (clientJwtConfig != null ? clientJwtConfig.hashCode() : 0);
        return result;
    }
}
