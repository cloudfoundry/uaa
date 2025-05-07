package org.cloudfoundry.identity.uaa;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class LimitedModePropertiesTest {

    @EnableConfigurationProperties({LimitedModeProperties.class, LimitedModeProperties.Permitted.class})
    static class TestLimitedModeConfig {}

    private ApplicationContextRunner applicationContextRunner;

    @BeforeEach
    void setup() {
        applicationContextRunner = new ApplicationContextRunner().withUserConfiguration(TestLimitedModeConfig.class);
    }

    @Test
    void whenNoPropertiesAreSet() {
        applicationContextRunner
                .run(context -> {
                    LimitedModeProperties properties = context.getBean(LimitedModeProperties.class);

                    assertThat(properties.statusFile).isNull();

                    assertThat(properties.permitted.endpoints()).isEmpty();
                    assertThat(properties.permitted.methods()).isEmpty();
                });
    }


    @Test
    void whenLimitedModePropertiesAreSet() {

        applicationContextRunner
                .withPropertyValues("uaa.limitedFunctionality.statusFile=/tmp/nonexistent/statusFile")
                .withPropertyValues("uaa.limitedFunctionality.whitelist.endpoints=e1,e2,e3")
                .withPropertyValues("uaa.limitedFunctionality.whitelist.methods=GET,OPTIONS")
                .run(context -> {
                    LimitedModeProperties properties = context.getBean(LimitedModeProperties.class);

                    assertThat(properties.statusFile).isNotNull();
                    assertThat(properties.statusFile.getAbsolutePath()).isEqualTo("/tmp/nonexistent/statusFile");

                    assertThat(properties.permitted.endpoints()).containsExactly("e1", "e2", "e3");
                    assertThat(properties.permitted.methods()).containsExactly("GET", "OPTIONS");
                });
    }

}
