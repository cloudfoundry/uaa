package org.cloudfoundry.identity.uaa.oauth.beans;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Conditional;

import static org.assertj.core.api.Assertions.assertThat;

class OauthEndpointSecurityConfigurationTests {

    @Test
    void mtlsSecurityChainIsAlwaysCreatedForRuntimeZonePolicy() throws NoSuchMethodException {
        Conditional conditional = OauthEndpointSecurityConfiguration.class
                .getDeclaredMethod("mtlsTokenEndpointSecurity",
                        org.springframework.security.config.annotation.web.builders.HttpSecurity.class)
                .getAnnotation(Conditional.class);

        assertThat(conditional)
                .as("zone policy must gate requests at runtime, without conditionally removing the security chain")
                .isNull();
    }
}
