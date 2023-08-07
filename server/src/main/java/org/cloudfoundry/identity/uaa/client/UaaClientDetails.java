package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
@JsonIgnoreProperties(ignoreUnknown = true)
public class UaaClientDetails extends BaseClientDetails {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    UaaClientDetails(ClientDetails prototype) {
        super(prototype);
        this.setAdditionalInformation(prototype.getAdditionalInformation());
    }

    public UaaClientDetails(String clientId, String clientSecret, String resourceIds,
        String scopes, String grantTypes, String authorities, String redirectUris) {
        super(clientId, resourceIds, scopes, grantTypes, authorities, redirectUris);
        setClientSecret(clientSecret);
    }

    @Override
    public void setScope(Collection<String> scope) {
        Set<String> sanitized = scope.stream()
                .flatMap(s -> Arrays.stream(s.split(",")))
                .collect(Collectors.toSet());
        super.setScope(sanitized);
    }
}
