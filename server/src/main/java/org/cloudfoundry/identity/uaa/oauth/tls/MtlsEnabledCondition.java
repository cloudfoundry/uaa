package org.cloudfoundry.identity.uaa.oauth.tls;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Gates a bean on {@code uaa.mtls-enabled} using <em>exactly</em> the same interpretation of the
 * value as {@code @Value("${uaa.mtls-enabled:false}") boolean}.
 *
 * <p>This exists because the two are otherwise not the same test.
 * {@code @ConditionalOnProperty(name = "uaa.mtls-enabled", havingValue = "true")} compares the raw
 * value to the literal string {@code "true"}, while a {@code boolean} injection point is converted by
 * the environment's conversion service, which also accepts {@code 1}, {@code yes} and {@code on}. So
 * {@code uaa.mtls-enabled=1} used to switch on the seven {@code @Value}-gated components -- the
 * availability filter, the certificate-mapper filter, both client validators, the bootstrap, the
 * Tomcat connector customizer and the discovery endpoint -- while leaving the two
 * {@code @ConditionalOnProperty} ones off: {@link MtlsClaimsEnhancer}, which stamps the RFC 8705
 * {@code cnf.x5t#S256} confirmation claim, and the {@code mtlsTokenEndpointSecurity} filter chain.
 *
 * <p>That half-enabled state is worse than either extreme. The endpoint is reachable and advertised
 * in discovery as issuing certificate-bound tokens, but nothing stamps {@code cnf} and the endpoint
 * has no OAuth security chain of its own, so the path falls through to the catch-all browser chain.
 * A resource server checking {@code cnf} would be told the opposite of the truth.
 *
 * <p>Reading through {@code Environment.getProperty(key, Boolean.class, false)} routes the value
 * through that same conversion service, so a bean gated by this condition is present on exactly the
 * values for which the {@code boolean} injection points see {@code true}. One switch, one meaning.
 */
public class MtlsEnabledCondition implements Condition {

    static final String MTLS_ENABLED_PROPERTY = "uaa.mtls-enabled";

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        return Boolean.TRUE.equals(
                context.getEnvironment().getProperty(MTLS_ENABLED_PROPERTY, Boolean.class, Boolean.FALSE));
    }
}
