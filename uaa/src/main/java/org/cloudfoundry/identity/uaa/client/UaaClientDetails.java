package org.cloudfoundry.identity.uaa.client;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class UaaClientDetails extends BaseClientDetails {
    UaaClientDetails(ClientDetails prototype) {
        super(prototype);
        this.setAdditionalInformation(prototype.getAdditionalInformation());
    }

    public void setScope(Collection<String> scope) {
        Set<String> sanitized = scope.stream()
                .flatMap(s -> Arrays.stream(s.split(",")))
                .collect(Collectors.toSet());
        super.setScope(sanitized);
    }
}
