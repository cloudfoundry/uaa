package org.cloudfoundry.identity.uaa.impl.config;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

class UaaConfigurationTokenKeyTest {

    private static final String tokenKeyYaml = getResourceAsString(UaaConfigurationTokenKeyTest.class, "JwtTokenKey.yaml");

    private final YamlConfigurationValidator<UaaConfiguration> validator = new YamlConfigurationValidator<>(
            new UaaConfiguration.UaaConfigConstructor());

    private UaaConfiguration createValidator(final String yaml) {
        validator.setExceptionIfInvalid(true);
        validator.setYaml(yaml);
        validator.afterPropertiesSet();
        return validator.getObject();
    }

    @Test
    void tokenKeyStructure() {
        UaaConfiguration uaaConfiguration = createValidator(tokenKeyYaml);
        assertThat(uaaConfiguration).isNotNull();
        Map<String, Object> uaa = uaaConfiguration.uaa;
        assertThat(uaa).isNotNull();
        Map<String, Object> jwt = (Map<String, Object>) uaa.get("jwt");
        assertThat(jwt).isNotNull();
        Map<String, Object> token = (Map<String, Object>) jwt.get("token");
        assertThat(token).isNotNull();
        Map<String, Object> policy = (Map<String, Object>) token.get("policy");
        assertThat(policy).isNotNull();
        Map<String, Object> keys = (Map<String, Object>) policy.get("keys");
        assertThat(keys).isNotNull();
        Map<String, Object> keyId1 = (Map<String, Object>) keys.get("key-id-1");
        assertThat(keyId1)
                .isNotNull()
                .containsEntry("signingCert", "cert")
                .containsEntry("signingKey", "key")
                .containsEntry("signingAlg", "PS256");
    }
}
