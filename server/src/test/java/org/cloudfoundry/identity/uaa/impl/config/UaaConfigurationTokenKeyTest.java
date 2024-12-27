package org.cloudfoundry.identity.uaa.impl.config;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    void testTokenKeyStructure() {
        UaaConfiguration uaaConfiguration = createValidator(tokenKeyYaml);
        assertNotNull(uaaConfiguration);
        Map<String, Object> uaa = uaaConfiguration.uaa;
        assertNotNull(uaa);
        Map<String, Object> jwt = (Map<String, Object>) uaa.get("jwt");
        assertNotNull(jwt);
        Map<String, Object> token = (Map<String, Object>) jwt.get("token");
        assertNotNull(token);
        Map<String, Object> policy = (Map<String, Object>) token.get("policy");
        assertNotNull(policy);
        Map<String, Object> keys = (Map<String, Object>) policy.get("keys");
        assertNotNull(keys);
        Map<String, Object> keyId1 = (Map<String, Object>) keys.get("key-id-1");
        assertNotNull(keyId1);
        assertEquals("cert", keyId1.get("signingCert"));
        assertEquals("key", keyId1.get("signingKey"));
        assertEquals("PS256", keyId1.get("signingAlg"));
    }
}