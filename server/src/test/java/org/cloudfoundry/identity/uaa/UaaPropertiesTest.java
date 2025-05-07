package org.cloudfoundry.identity.uaa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class UaaPropertiesTest {

    @EnableConfigurationProperties({
            UaaProperties.DefaultClientSecretPolicy.class,
            UaaProperties.Logout.class,
            UaaProperties.Servlet.class,
            UaaProperties.Csp.class,
            UaaProperties.Metrics.class
    })
    static class TestUaaServletConfig {}

    private ApplicationContextRunner applicationContextRunner;

    @BeforeEach
    void setup() {
        applicationContextRunner = new ApplicationContextRunner().withUserConfiguration(TestUaaServletConfig.class);
    }

    @Test
    void whenNoLogoutPropertiesAreSet() {
        applicationContextRunner
                .run(context -> {
                    UaaProperties.Logout properties = context.getBean(UaaProperties.Logout.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.redirect()).isNotNull();
                    assertThat(properties.redirect().url()).isEqualTo("/login");
                    assertThat(properties.redirect().parameter()).isNotNull();
                    assertThat(properties.redirect().parameter().whitelist()).isNotNull();
                    assertThat(properties.redirect().parameter().whitelist()).isEmpty();
                    assertThat(properties.redirect().parameter().disable()).isFalse();
                });
    }

    @Test
    void whenLogoutPropertiesAreSet() {
        applicationContextRunner
                .withPropertyValues("logout.redirect.url=/login2")
                .withPropertyValues("logout.redirect.parameter.disable=true")
                .withPropertyValues("logout.redirect.parameter.whitelist=http://url1,http://url2")
                .run(context -> {
                    UaaProperties.Logout properties = context.getBean(UaaProperties.Logout.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.redirect()).isNotNull();
                    assertThat(properties.redirect().url()).isEqualTo("/login2");
                    assertThat(properties.redirect().parameter()).isNotNull();
                    assertThat(properties.redirect().parameter().whitelist()).isNotNull();
                    assertThat(properties.redirect().parameter().whitelist()).containsExactly("http://url1", "http://url2");
                    assertThat(properties.redirect().parameter().disable()).isTrue();
                });
    }

    @Test
    void whenNoServletPropertiesAreSet() {
        applicationContextRunner
                .run(context -> {
                    UaaProperties.Servlet properties = context.getBean(UaaProperties.Servlet.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.filteredHeaders()).isNotNull();
                    assertThat(properties.filteredHeaders()).containsExactly(
                            "X-Forwarded-For",
                            "X-Forwarded-Host",
                            "X-Forwarded-Proto",
                            "X-Forwarded-Prefix",
                            "Forwarded"
                    );

                });
    }

    @Test
    void whenFilteredHeadersAreSet() {
        applicationContextRunner
                .withPropertyValues("servlet.filtered-headers=X-Forwarded-Host,X-Forwarded-Proto")
                .run(context -> {
                    UaaProperties.Servlet properties = context.getBean(UaaProperties.Servlet.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.filteredHeaders()).isNotNull();
                    assertThat(properties.filteredHeaders()).containsExactly(
                            "X-Forwarded-Host",
                            "X-Forwarded-Proto"
                    );

                });
    }

    @Test
    void whenNoCspPropertiesAreSet() {
        applicationContextRunner
                .run(context -> {
                    UaaProperties.Csp properties = context.getBean(UaaProperties.Csp.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.scriptSrc()).isNotNull();
                    assertThat(properties.scriptSrc()).containsExactly(
                            "'self'"
                    );

                });
    }

    @Test
    void whenCspPropertiesAreSet() {
        applicationContextRunner
                .withPropertyValues("csp.script-src='self',custom")
                .run(context -> {
                    UaaProperties.Csp properties = context.getBean(UaaProperties.Csp.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.scriptSrc()).isNotNull();
                    assertThat(properties.scriptSrc()).containsExactly(
                            "'self'", "custom"
                    );

                });
    }

    @Test
    void whenNoMetricsPropertiesAreSet() {
        applicationContextRunner
                .run(context -> {
                    UaaProperties.Metrics properties = context.getBean(UaaProperties.Metrics.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.enabled()).isTrue();
                    assertThat(properties.perRequestMetrics()).isFalse();

                });
    }

    @Test
    void whenMetricsPropertiesAreSet() {
        applicationContextRunner
                .withPropertyValues("metrics.enabled=false", "metrics.perRequestMetrics=true")
                .run(context -> {
                    UaaProperties.Metrics properties = context.getBean(UaaProperties.Metrics.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.enabled()).isFalse();
                    assertThat(properties.perRequestMetrics()).isTrue();

                });
    }

    @Test
    void whenClientSecretPolicyPropertiesAreNotSet() {
        applicationContextRunner
                .run(context -> {
                    UaaProperties.DefaultClientSecretPolicy properties = context.getBean(UaaProperties.DefaultClientSecretPolicy.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.global()).isNotNull();
                    assertThat(properties.global().minLength()).isEqualTo(0);
                    assertThat(properties.global().maxLength()).isEqualTo(255);
                    assertThat(properties.global().requireUpperCaseCharacter()).isEqualTo(0);
                    assertThat(properties.global().requireLowerCaseCharacter()).isEqualTo(0);
                    assertThat(properties.global().requireDigit()).isEqualTo(0);
                    assertThat(properties.global().requireSpecialCharacter()).isEqualTo(0);
                    assertThat(properties.global().expireSecretInMonths()).isEqualTo(0);

                    assertThat(properties.minLength()).isEqualTo(properties.global().minLength());
                    assertThat(properties.maxLength()).isEqualTo(properties.global().maxLength());
                    assertThat(properties.requireUpperCaseCharacter()).isEqualTo(properties.global().requireUpperCaseCharacter());
                    assertThat(properties.requireLowerCaseCharacter()).isEqualTo(properties.global().requireLowerCaseCharacter());
                    assertThat(properties.requireDigit()).isEqualTo(properties.global().requireDigit());
                    assertThat(properties.requireSpecialCharacter()).isEqualTo(properties.global().requireSpecialCharacter());
                    assertThat(properties.expireSecretInMonths()).isEqualTo(properties.global().expireSecretInMonths());
                });
    }

    @Test
    void whenGlobalClientSecretPolicyPropertiesAreSet() {
        applicationContextRunner
                .withPropertyValues("oauth.client.secret.policy.global.minLength=1")
                .withPropertyValues("oauth.client.secret.policy.global.maxLength=2")
                .withPropertyValues("oauth.client.secret.policy.global.requireUpperCaseCharacter=3")
                .withPropertyValues("oauth.client.secret.policy.global.requireLowerCaseCharacter=4")
                .withPropertyValues("oauth.client.secret.policy.global.requireDigit=5")
                .withPropertyValues("oauth.client.secret.policy.global.requireSpecialCharacter=6")
                .withPropertyValues("oauth.client.secret.policy.global.expireSecretInMonths=7")
                .run(context -> {
                    UaaProperties.DefaultClientSecretPolicy properties = context.getBean(UaaProperties.DefaultClientSecretPolicy.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.global()).isNotNull();
                    assertThat(properties.global().minLength()).isEqualTo(1);
                    assertThat(properties.global().maxLength()).isEqualTo(2);
                    assertThat(properties.global().requireUpperCaseCharacter()).isEqualTo(3);
                    assertThat(properties.global().requireLowerCaseCharacter()).isEqualTo(4);
                    assertThat(properties.global().requireDigit()).isEqualTo(5);
                    assertThat(properties.global().requireSpecialCharacter()).isEqualTo(6);
                    assertThat(properties.global().expireSecretInMonths()).isEqualTo(7);

                    assertThat(properties.minLength()).isEqualTo(properties.global().minLength());
                    assertThat(properties.maxLength()).isEqualTo(properties.global().maxLength());
                    assertThat(properties.requireUpperCaseCharacter()).isEqualTo(properties.global().requireUpperCaseCharacter());
                    assertThat(properties.requireLowerCaseCharacter()).isEqualTo(properties.global().requireLowerCaseCharacter());
                    assertThat(properties.requireDigit()).isEqualTo(properties.global().requireDigit());
                    assertThat(properties.requireSpecialCharacter()).isEqualTo(properties.global().requireSpecialCharacter());
                    assertThat(properties.expireSecretInMonths()).isEqualTo(properties.global().expireSecretInMonths());
                });
    }

    @Test
    void whenDefaultClientSecretPolicyPropertiesAreSet() {
        applicationContextRunner
                .withPropertyValues("oauth.client.secret.policy.minLength=1")
                .withPropertyValues("oauth.client.secret.policy.maxLength=2")
                .withPropertyValues("oauth.client.secret.policy.requireUpperCaseCharacter=3")
                .withPropertyValues("oauth.client.secret.policy.requireLowerCaseCharacter=4")
                .withPropertyValues("oauth.client.secret.policy.requireDigit=5")
                .withPropertyValues("oauth.client.secret.policy.requireSpecialCharacter=6")
                .withPropertyValues("oauth.client.secret.policy.expireSecretInMonths=7")

                .run(context -> {
                    UaaProperties.DefaultClientSecretPolicy properties = context.getBean(UaaProperties.DefaultClientSecretPolicy.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.global()).isNotNull();

                    assertThat(properties.global().minLength()).isEqualTo(0);
                    assertThat(properties.global().maxLength()).isEqualTo(255);
                    assertThat(properties.global().requireUpperCaseCharacter()).isEqualTo(0);
                    assertThat(properties.global().requireLowerCaseCharacter()).isEqualTo(0);
                    assertThat(properties.global().requireDigit()).isEqualTo(0);
                    assertThat(properties.global().requireSpecialCharacter()).isEqualTo(0);
                    assertThat(properties.global().expireSecretInMonths()).isEqualTo(0);

                    assertThat(properties.minLength()).isEqualTo(1);
                    assertThat(properties.maxLength()).isEqualTo(2);
                    assertThat(properties.requireUpperCaseCharacter()).isEqualTo(3);
                    assertThat(properties.requireLowerCaseCharacter()).isEqualTo(4);
                    assertThat(properties.requireDigit()).isEqualTo(5);
                    assertThat(properties.requireSpecialCharacter()).isEqualTo(6);
                    assertThat(properties.expireSecretInMonths()).isEqualTo(7);
                });
    }

    @Test
    void whenDefaultAndGlobalClientSecretPolicyPropertiesAreSet() {
        applicationContextRunner
                .withPropertyValues("oauth.client.secret.policy.minLength=1")
                .withPropertyValues("oauth.client.secret.policy.maxLength=2")
                .withPropertyValues("oauth.client.secret.policy.requireUpperCaseCharacter=3")
                .withPropertyValues("oauth.client.secret.policy.requireLowerCaseCharacter=4")
                .withPropertyValues("oauth.client.secret.policy.requireDigit=5")
                .withPropertyValues("oauth.client.secret.policy.requireSpecialCharacter=6")
                .withPropertyValues("oauth.client.secret.policy.expireSecretInMonths=7")
                .withPropertyValues("oauth.client.secret.policy.global.minLength=8")
                .withPropertyValues("oauth.client.secret.policy.global.maxLength=9")
                .withPropertyValues("oauth.client.secret.policy.global.requireUpperCaseCharacter=10")
                .withPropertyValues("oauth.client.secret.policy.global.requireLowerCaseCharacter=11")
                .withPropertyValues("oauth.client.secret.policy.global.requireDigit=12")
                .withPropertyValues("oauth.client.secret.policy.global.requireSpecialCharacter=13")
                .withPropertyValues("oauth.client.secret.policy.global.expireSecretInMonths=14")
                .run(context -> {
                    UaaProperties.DefaultClientSecretPolicy properties = context.getBean(UaaProperties.DefaultClientSecretPolicy.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.global()).isNotNull();

                    assertThat(properties.global().minLength()).isEqualTo(8);
                    assertThat(properties.global().maxLength()).isEqualTo(9);
                    assertThat(properties.global().requireUpperCaseCharacter()).isEqualTo(10);
                    assertThat(properties.global().requireLowerCaseCharacter()).isEqualTo(11);
                    assertThat(properties.global().requireDigit()).isEqualTo(12);
                    assertThat(properties.global().requireSpecialCharacter()).isEqualTo(13);
                    assertThat(properties.global().expireSecretInMonths()).isEqualTo(14);

                    assertThat(properties.minLength()).isEqualTo(1);
                    assertThat(properties.maxLength()).isEqualTo(2);
                    assertThat(properties.requireUpperCaseCharacter()).isEqualTo(3);
                    assertThat(properties.requireLowerCaseCharacter()).isEqualTo(4);
                    assertThat(properties.requireDigit()).isEqualTo(5);
                    assertThat(properties.requireSpecialCharacter()).isEqualTo(6);
                    assertThat(properties.expireSecretInMonths()).isEqualTo(7);
                });
    }
}