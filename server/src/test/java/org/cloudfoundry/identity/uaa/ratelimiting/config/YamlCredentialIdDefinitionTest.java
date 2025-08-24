package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

class YamlCredentialIdDefinitionTest {

    @Test
    void from() {
        assertThat(YamlCredentialIdDefinition.from(null)).isNull();
        assertThat(YamlCredentialIdDefinition.from("  ")).isNull(); // a little testing to imply usage of StringUtils.normalizeToNull
        assertValues("Fred", null, YamlCredentialIdDefinition.from(" Fred "));
        assertValues("Fred", null, YamlCredentialIdDefinition.from("Fred:"));
        assertValues("Redish", "Yellow", YamlCredentialIdDefinition.from(" Redish : Yellow "));

        try {
            YamlCredentialIdDefinition definition = YamlCredentialIdDefinition.from("  : Yellow ");
            fail("expected Exception, but got: " + definition);
        } catch (RateLimitingConfigException expected) {
            String msg = expected.getMessage();
            if (!msg.startsWith(YamlCredentialIdDefinition.EMPTY_KEY_FROM_PREFIX)) {
                fail("expected exception message did not start with '" +
                        YamlCredentialIdDefinition.EMPTY_KEY_FROM_PREFIX + "', msg was: " + msg);
            }
        }
    }

    private void assertValues(String expectedKey, String expectedPostKeyConfig, YamlCredentialIdDefinition definition) {
        assertThat(definition).as(expectedKey).isNotNull();
        assertThat(definition.getKey()).isEqualTo(expectedKey);
        assertThat(definition.getPostKeyConfig()).as(expectedKey).isEqualTo(expectedPostKeyConfig);
    }
}