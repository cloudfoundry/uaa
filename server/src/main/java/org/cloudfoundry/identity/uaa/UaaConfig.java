package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for application-wide beans, as well as "infrastructure" beans
 * that help enable other beans (e.g. during the migration from XML config to Java config).
 */
@Configuration
@EnableConfigurationProperties({
        UaaProperties.Uaa.class,
        UaaProperties.Servlet.class,
        UaaProperties.RootLevel.class
})
public class UaaConfig {

    /**
     * Represents the Spring Security Filter Chain bean we are using in the application.
     */
    public static final String SPRING_SECURITY_FILTER_CHAIN_ID = "aggregateSpringSecurityFilterChain";

    @Bean
    public KeyInfoService keyInfoService(UaaProperties.Uaa uaaProperties) {
        return new KeyInfoService(uaaProperties.url());
    }

    /**
     * Creates an "aggregate" {@link FilterChainProxy} that contains filter chains registered both
     * through XML config and Java config.
     * <p>
     * It is not possible to mix Java-based configuration and XML-based configuration for Spring
     * Security out of the box. XML-based {@code <http>} elements are registered in a
     * {@link FilterChainProxy} before any bean of type {@link SecurityFilterChain} are created.
     * Any {@link Bean} of type SecurityFilterChain created in java configuration is, by default,
     * not loaded in the Security configuration.
     * <p>
     * This method creates a {@link FilterChainProxy} bean that will be used instead of the default
     * {@code springSecurityFilterChain} which only contains XML chains. By calling
     * {@link WebSecurityConfiguration#springSecurityFilterChain()} explicitly inside a {@link Bean}
     * method, we are catching both types of filter chains. By default, Java-based filter chains are
     * registered before XML-based filter chains.
     * <p>
     * Java-based filter chains should be inserted last. We inject them as {@link UaaFilterChain}s,
     * to tell them apart from XML, and reorder the default {@link FilterChainProxy} to put those
     * in the last positions.
     * <p>
     * This filter chain is then registered as a filter, by name in {@code web.xml}.
     *
     * @see <a href="https://github.com/spring-projects/spring-security/issues/11108#issuecomment-1113608990">Spring Security #11108</a>
     * @deprecated Remove this once there are no more XML-based filter chains.
     */
    @Bean(name = SPRING_SECURITY_FILTER_CHAIN_ID)
    public FilterChainProxy aggregateSpringSecurityFilterChain(WebSecurityConfiguration webSecurityConfiguration, List<UaaFilterChain> javaFilterChains) throws Exception {
        var xmlFilterChains = ((FilterChainProxy) webSecurityConfiguration.springSecurityFilterChain()).getFilterChains();
        var securityFilterChains = new ArrayList<>(xmlFilterChains);
        securityFilterChains.removeAll(javaFilterChains);
        securityFilterChains.addAll(javaFilterChains);

        return new FilterChainProxy(securityFilterChains);
    }

}
