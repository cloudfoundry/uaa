package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class YamlLoggingOptionTest {

    @Test
    void from() {
        assertThat(YamlLoggingOption.from(null)).isNull();
        assertThat(YamlLoggingOption.from("  ")).isNull(); // a little testing to imply usage of StringUtils.normalizeToNull
        YamlLoggingOption option = YamlLoggingOption.from(" Fred ");
        assertThat(option).isNotNull();
        assertThat(option.getValue()).isEqualTo("Fred");
    }
}