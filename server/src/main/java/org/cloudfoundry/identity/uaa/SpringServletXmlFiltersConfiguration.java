package org.cloudfoundry.identity.uaa;

import org.apache.catalina.filters.HttpHeaderSecurityFilter;
import org.cloudfoundry.identity.uaa.authentication.SessionResetFilter;
import org.cloudfoundry.identity.uaa.authentication.UTF8ConversionFilter;
import org.cloudfoundry.identity.uaa.metrics.UaaMetricsFilter;
import org.cloudfoundry.identity.uaa.oauth.DisableIdTokenResponseTypeFilter;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.ratelimiting.RateLimitingFilter;
import org.cloudfoundry.identity.uaa.scim.DisableInternalUserManagementFilter;
import org.cloudfoundry.identity.uaa.scim.DisableUserManagementSecurityFilter;
import org.cloudfoundry.identity.uaa.security.web.ContentSecurityPolicyFilter;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.web.HeaderFilter;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneResolvingFilter;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.web.filter.RequestContextFilter;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;

@Configuration
@EnableWebSecurity
public class SpringServletXmlFiltersConfiguration {

    @Autowired
    CorsProperties corsProperties;

    @Autowired
    LimitedModeProperties limitedModeProperties;

    @Autowired
    UaaProperties.Servlet servletProps;

    @Autowired
    UaaProperties.Csp cspProps;

    @Autowired
    UaaProperties.Metrics metricsProps;

    @Autowired
    UaaProperties.Uaa uaaProps;

    @Autowired
    UaaProperties.Login loginProps;

    @Autowired
    UaaProperties.Zones zoneProps;

    @Autowired
    IdentityZoneManager identityZoneManager;

    @Bean
    DisableIdTokenResponseTypeFilter disableIdTokenResponseFilter(
            @Value("${oauth.id_token.disable:false}") boolean disable
    ) {
        DisableIdTokenResponseTypeFilter bean = new DisableIdTokenResponseTypeFilter(
                disable,
                Arrays.asList("/**/oauth/authorize", "/oauth/authorize")
        );
        return bean;
    }

    @Bean
    UTF8ConversionFilter utf8ConversionFilter() {
        return new UTF8ConversionFilter();
    }

    @Bean
    CorsFilter corsFilter() {
        CorsFilter bean = new CorsFilter(identityZoneManager, corsProperties.enforceSystemZoneSettings);

        bean.setCorsAllowedUris(corsProperties.defaultAllowed.uris());
        bean.setCorsAllowedOrigins(corsProperties.defaultAllowed.origins());
        bean.setCorsAllowedHeaders(corsProperties.defaultAllowed.headers());
        bean.setCorsAllowedMethods(corsProperties.defaultAllowed.methods());
        bean.setCorsAllowedCredentials(corsProperties.defaultAllowed.credentials());
        bean.setCorsMaxAge(corsProperties.defaultMaxAge);

        bean.setCorsXhrAllowedUris(corsProperties.xhrAllowed.uris());
        bean.setCorsXhrAllowedOrigins(corsProperties.xhrAllowed.origins());
        bean.setCorsXhrAllowedHeaders(corsProperties.xhrAllowed.headers());
        bean.setCorsXhrAllowedMethods(corsProperties.xhrAllowed.methods());
        bean.setCorsXhrAllowedCredentials(corsProperties.xhrAllowed.credentials());
        bean.setCorsXhrMaxAge(corsProperties.xhrMaxAge);
        return bean;
    }

    @Bean
    LimitedModeUaaFilter limitedModeUaaFilter() {
        LimitedModeUaaFilter bean = new LimitedModeUaaFilter();
        bean.setStatusFile(limitedModeProperties.statusFile);
        bean.setPermittedEndpoints(limitedModeProperties.permitted.endpoints());
        bean.setPermittedMethods(limitedModeProperties.permitted.methods());
        return bean;
    }

    @Bean
    HeaderFilter headerFilter(

    ) {
        return new HeaderFilter(servletProps.filteredHeaders());
    }

    @Bean
    ContentSecurityPolicyFilter contentSecurityPolicyFilter() {
        return new ContentSecurityPolicyFilter(cspProps.scriptSrc());
    }

    @Bean
    UaaMetricsFilter metricsFilter(TimeService timeService) throws IOException {
        return new UaaMetricsFilter(metricsProps.enabled(), metricsProps.perRequestMetrics(), timeService);
    }

    @Bean
    DisableUserManagementSecurityFilter userManagementSecurityFilter(
            @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning
    ) {
        return new DisableUserManagementSecurityFilter(provisioning, identityZoneManager);
    }

    @Bean
    DisableInternalUserManagementFilter userManagementFilter(
            @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning
    ) {
        return new DisableInternalUserManagementFilter(provisioning, identityZoneManager);
    }

    @Bean
    IdentityZoneResolvingFilter identityZoneResolvingFilter(IdentityZoneProvisioning provisioning) {
        IdentityZoneResolvingFilter bean = new IdentityZoneResolvingFilter(provisioning);
        bean.setDefaultInternalHostnames(new HashSet<>(Arrays.asList(
                UaaUrlUtils.getHostForURI(uaaProps.url()),
                UaaUrlUtils.getHostForURI(loginProps.url()),
                "localhost"
        )));
        bean.setAdditionalInternalHostnames(zoneProps.internal().hostnames());
        return bean;
    }

    @Bean
    SessionResetFilter sessionResetFilter(@Qualifier("userDatabase") JdbcUaaUserDatabase userDatabase) {
        return new SessionResetFilter(
                new DefaultRedirectStrategy(),
                "/login",
                userDatabase
        );
    }

    @Bean
    IdentityZoneSwitchingFilter identityZoneSwitchingFilter(IdentityZoneProvisioning provisioning) {
        return new IdentityZoneSwitchingFilter(provisioning);
    }

    @Bean
    RateLimitingFilter rateLimitingFilter() throws ServletException {
        return new RateLimitingFilter();
    }

    @Bean
    RequestContextFilter springRequestContextFilter() {
        return new RequestContextFilter();
    }

    @Bean
    public HttpHeaderSecurityFilter httpHeaderSecurityFilter() {
        HttpHeaderSecurityFilter httpHeaderSecurityFilter = new HttpHeaderSecurityFilter();
        httpHeaderSecurityFilter.setHstsEnabled(false);
        httpHeaderSecurityFilter.setAntiClickJackingEnabled(false);
        httpHeaderSecurityFilter.setBlockContentTypeSniffingEnabled(true);
        httpHeaderSecurityFilter.setXssProtectionEnabled(false);
        return httpHeaderSecurityFilter;
    }
}
