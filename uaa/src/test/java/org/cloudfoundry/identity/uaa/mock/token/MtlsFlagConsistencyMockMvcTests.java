package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.oauth.tls.MtlsClaimsEnhancer;
import org.cloudfoundry.identity.uaa.oauth.tls.MtlsEndpointAvailabilityFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.context.WebApplicationContext;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code uaa.mtls-enabled} is read two different ways, and the two do not agree on what counts as
 * true.
 *
 * <ul>
 *   <li>{@code @ConditionalOnProperty(name = "uaa.mtls-enabled", havingValue = "true")} gates
 *       {@link MtlsClaimsEnhancer} (which stamps the RFC 8705 {@code cnf.x5t#S256} claim) and the
 *       {@code mtlsTokenEndpointSecurity} filter chain. Spring compares the raw value to the string
 *       {@code "true"}, case-insensitively.</li>
 *   <li>{@code @Value("${uaa.mtls-enabled:false}") boolean} gates the other seven: the availability
 *       filter, the certificate-mapper filter, both client validators, the bootstrap, the Tomcat
 *       connector customizer and the discovery endpoint. Spring converts through
 *       {@code StringToBooleanConverter}, which also accepts {@code 1}, {@code yes} and {@code on}.
 *       </li>
 * </ul>
 *
 * <p>So a value like {@code 1} turns the second group on and leaves the first group off. The
 * property is a single switch and must behave like one: either the feature is on everywhere or off
 * everywhere. A half-on deployment is the worst of both -- the endpoint is reachable and advertised,
 * while the code that makes tokens issued there certificate-bound is absent.
 */
@DefaultTestContext
@TestPropertySource(properties = {"uaa.mtls-enabled=1"})
class MtlsFlagConsistencyMockMvcTests {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Qualifier("mtlsEndpointAvailabilityFilter")
    @Autowired
    FilterRegistrationBean<MtlsEndpointAvailabilityFilter> mtlsEndpointAvailabilityFilterRegistration;

    @Test
    @DisplayName("K1. a truthy-but-not-\"true\" flag value must not half-enable the feature")
    void alternativeTruthySpellingDoesNotHalfEnableMtls() throws Exception {
        // The @Value-gated half: is the endpoint being served?
        boolean endpointServed = isEndpointEnabled();

        // The @ConditionalOnProperty-gated half: is the cnf-stamping enhancer present?
        boolean cnfEnhancerPresent =
                webApplicationContext.getBeanNamesForType(MtlsClaimsEnhancer.class).length > 0;
        // ...and the endpoint's own OAuth security chain?
        boolean mtlsSecurityChainPresent =
                webApplicationContext.containsBean("mtlsTokenEndpointSecurity");

        assertThat(cnfEnhancerPresent)
                .as("the endpoint is %s, so the cnf-stamping enhancer must be in the same state -- "
                        + "otherwise /oauth/mtls/token issues tokens that are NOT certificate-bound "
                        + "while discovery advertises that they are",
                        endpointServed ? "served" : "not served")
                .isEqualTo(endpointServed);

        assertThat(mtlsSecurityChainPresent)
                .as("the endpoint is %s, so its OAuth security chain must be in the same state -- "
                        + "otherwise the path falls through to the catch-all browser chain",
                        endpointServed ? "served" : "not served")
                .isEqualTo(endpointServed);
    }

    /**
     * Whether the availability filter would serve the endpoint, i.e. whether its {@code mtlsEnabled}
     * came out true. Read through behaviour rather than reflection: a disabled filter answers 404 for
     * the mTLS path instead of passing the request down the chain.
     */
    private boolean isEndpointEnabled() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/mtls/token");
        request.setServletPath("/oauth/mtls/token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean passedThrough = new AtomicBoolean(false);

        mtlsEndpointAvailabilityFilterRegistration.getFilter()
                .doFilter(request, response, (req, res) -> passedThrough.set(true));

        return passedThrough.get();
    }
}
