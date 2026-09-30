package org.cloudfoundry.identity.uaa.oauth.tls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The point of this condition is that it agrees with {@code @Value("${uaa.mtls-enabled:false}")
 * boolean}, which is how the other seven components in the feature are gated. Both route the value
 * through the environment's conversion service, so these cases are really pinning that agreement:
 * anything the {@code boolean} injection points treat as true must produce a matching condition, or
 * the feature can be half-enabled.
 */
class MtlsEnabledConditionTest {

    private final MtlsEnabledCondition condition = new MtlsEnabledCondition();

    @ParameterizedTest
    @ValueSource(strings = {"true", "TRUE", "True", "1", "yes", "on"})
    void matchesEverySpellingTheBooleanInjectionPointsAcceptAsTrue(String value) {
        assertThat(condition.matches(contextWith(value), null))
                .as("uaa.mtls-enabled=%s enables the @Value-gated components, so it must enable the "
                        + "@Conditional-gated ones too -- otherwise the endpoint is served with no "
                        + "cnf-stamping enhancer and no security chain", value)
                .isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "FALSE", "0", "no", "off"})
    void doesNotMatchAnySpellingTreatedAsFalse(String value) {
        assertThat(condition.matches(contextWith(value), null))
                .as("uaa.mtls-enabled=%s must leave the feature off everywhere", value)
                .isFalse();
    }

    @Test
    void doesNotMatchWhenThePropertyIsAbsent() {
        assertThat(condition.matches(contextWith(null), null))
                .as("the product default is off, so an absent property must not enable anything")
                .isFalse();
    }

    private static ConditionContext contextWith(String mtlsEnabled) {
        MockEnvironment environment = new MockEnvironment();
        if (mtlsEnabled != null) {
            environment.setProperty(MtlsEnabledCondition.MTLS_ENABLED_PROPERTY, mtlsEnabled);
        }
        ConditionContext context = mock(ConditionContext.class);
        when(context.getEnvironment()).thenReturn((Environment) environment);
        return context;
    }
}
