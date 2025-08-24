package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UaaSamlPrincipalTest {
    @Test
    void uaaSamlPrincipal() {
        UaaSamlPrincipal uaaSamlPrincipal = new UaaSamlPrincipal("id", "name", "email", "origin", List.of("sessionIndexes"), "externalId", "zoneId");
        assertThat(uaaSamlPrincipal).returns("id", UaaSamlPrincipal::getId)
                .returns("name", UaaSamlPrincipal::getName)
                .returns("email", UaaSamlPrincipal::getEmail)
                .returns("origin", UaaSamlPrincipal::getOrigin)
                .returns("origin", UaaSamlPrincipal::getRelyingPartyRegistrationId)
                .returns("externalId", UaaSamlPrincipal::getExternalId)
                .returns("zoneId", UaaSamlPrincipal::getZoneId);
    }
}
