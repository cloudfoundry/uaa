package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class YamlLoggingOptionTest {

    @Test
    void from() {
        assertNull(YamlLoggingOption.from(null));
        assertNull(YamlLoggingOption.from("  ")); // a little testing to imply usage of StringUtils.normalizeToNull
        YamlLoggingOption option = YamlLoggingOption.from(" Fred ");
        assertNotNull(option);
        assertEquals("Fred", option.getValue());
    }
}