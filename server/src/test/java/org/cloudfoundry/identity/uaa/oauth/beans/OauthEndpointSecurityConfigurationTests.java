package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.oauth.tls.MtlsEnabledCondition;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Conditional;

import static org.assertj.core.api.Assertions.assertThat;

class OauthEndpointSecurityConfigurationTests {

    /**
     * The chain must be gated on {@code uaa.mtls-enabled}, and specifically through
     * {@link MtlsEnabledCondition} rather than {@code @ConditionalOnProperty}. The two do not agree
     * on what counts as true: {@code havingValue = "true"} compares the raw string, while the rest of
     * the feature is gated by {@code boolean} injection points that also accept {@code 1}, {@code yes}
     * and {@code on}. With the annotation, {@code uaa.mtls-enabled=1} left this chain absent while the
     * endpoint was still served — see {@code MtlsEnabledConditionTest} and
     * {@code MtlsFlagConsistencyMockMvcTests}.
     */
    @Test
    void createsMtlsTokenSecurityChainOnlyWhenMtlsIsEnabled() throws NoSuchMethodException {
        Conditional conditional = OauthEndpointSecurityConfiguration.class
                .getDeclaredMethod("mtlsTokenEndpointSecurity",
                        org.springframework.security.config.annotation.web.builders.HttpSecurity.class)
                .getAnnotation(Conditional.class);

        assertThat(conditional)
                .as("the mTLS token endpoint's security chain must not exist on a deployment that has "
                        + "not enabled the feature")
                .isNotNull();
        assertThat(conditional.value())
                .as("it must use the same reading of the flag as the rest of the feature")
                .containsExactly(MtlsEnabledCondition.class);
    }
}
