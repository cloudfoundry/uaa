package org.cloudfoundry.identity.uaa.oauth.beans;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import static org.assertj.core.api.Assertions.assertThat;

class OauthEndpointSecurityConfigurationTests {

    @Test
    void createsMtlsTokenSecurityChainOnlyWhenMtlsIsEnabled() throws NoSuchMethodException {
        ConditionalOnProperty condition = OauthEndpointSecurityConfiguration.class
                .getDeclaredMethod("mtlsTokenEndpointSecurity", org.springframework.security.config.annotation.web.builders.HttpSecurity.class)
                .getAnnotation(ConditionalOnProperty.class);

        assertThat(condition).isNotNull();
        assertThat(condition.name()).containsExactly("uaa.mtls-enabled");
        assertThat(condition.havingValue()).isEqualTo("true");
    }
}
