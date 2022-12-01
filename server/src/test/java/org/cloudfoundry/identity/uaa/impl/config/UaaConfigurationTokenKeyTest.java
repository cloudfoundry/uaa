package org.cloudfoundry.identity.uaa.impl.config;

import org.junit.jupiter.api.Test;


class UaaConfigurationTokenKeyTest {

  private YamlConfigurationValidator<UaaConfiguration> validator = new YamlConfigurationValidator<UaaConfiguration>(
      new UaaConfiguration.UaaConfigConstructor());

  private void createValidator(final String yaml) {
    validator.setExceptionIfInvalid(true);
    validator.setYaml(yaml);
    validator.afterPropertiesSet();
  }

  @Test
  void testTokenKey() {
    createValidator("uaa:\n" +
        "  jwt:\n" +
        "    token:\n" +
        "      policy:\n" +
        "        activeKeyId: key-id-1\n" +
        "        keys:\n" +
        "          key-id-1:\n" +
        "            signingAlg: PS256\n" +
        "            signingKey: key\n" +
        "            signingCert: cert\n" +
        "");
  }
}