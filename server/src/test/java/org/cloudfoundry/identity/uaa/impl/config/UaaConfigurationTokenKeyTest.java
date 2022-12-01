package org.cloudfoundry.identity.uaa.impl.config;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class UaaConfigurationTokenKeyTest {

  private YamlConfigurationValidator<UaaConfiguration> validator = new YamlConfigurationValidator<UaaConfiguration>(
      new UaaConfiguration.UaaConfigConstructor());

  private UaaConfiguration createValidator(final String yaml) {
    validator.setExceptionIfInvalid(true);
    validator.setYaml(yaml);
    validator.afterPropertiesSet();
    return validator.getObject();
  }

  @Test
  void testTokenKey() {
    assertNotNull(createValidator("uaa:\n" +
        "  jwt:\n" +
        "    token:\n" +
        "      policy:\n" +
        "        activeKeyId: key-id-1\n" +
        "        keys:\n" +
        "          key-id-1:\n" +
        "            signingAlg: PS256\n" +
        "            signingKey: key\n" +
        "            signingCert: cert\n" +
        ""));
  }
}