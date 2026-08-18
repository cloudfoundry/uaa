package org.cloudfoundry.identity.uaa;

import org.apache.catalina.filters.HttpHeaderSecurityFilter;
import org.cloudfoundry.identity.uaa.authentication.SessionResetFilter;
import org.cloudfoundry.identity.uaa.metrics.UaaMetrics;
import org.cloudfoundry.identity.uaa.metrics.UaaMetricsFilter;
import org.cloudfoundry.identity.uaa.metrics.UaaMetricsManagedBean;
import org.cloudfoundry.identity.uaa.oauth.DisableIdTokenResponseTypeFilter;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.ratelimiting.RateLimitingFilter;
import org.cloudfoundry.identity.uaa.scim.DisableInternalUserManagementFilter;
import org.cloudfoundry.identity.uaa.scim.DisableUserManagementSecurityFilter;
import org.cloudfoundry.identity.uaa.security.web.ContentSecurityPolicyFilter;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
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
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.web.filter.RequestContextFilter;

import jakarta.servlet.ServletException;
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
    FilterRegistrationBean<DisableIdTokenResponseTypeFilter> disableIdTokenResponseFilter(
            @Value("${oauth.id_token.disable:false}") boolean disable
    ) {
        DisableIdTokenResponseTypeFilter filter = new DisableIdTokenResponseTypeFilter(
                disable,
                Arrays.asList("/**/oauth/authorize", "/oauth/authorize")
        );
        FilterRegistrationBean<DisableIdTokenResponseTypeFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<CorsFilter> corsFilter() {
        CorsFilter filter = new CorsFilter(identityZoneManager, corsProperties.enforceSystemZoneSettings);

        filter.setCorsAllowedUris(corsProperties.defaultAllowed.uris());
        filter.setCorsAllowedOrigins(corsProperties.defaultAllowed.origins());
        filter.setCorsAllowedHeaders(corsProperties.defaultAllowed.headers());
        filter.setCorsAllowedMethods(corsProperties.defaultAllowed.methods());
        filter.setCorsAllowedCredentials(corsProperties.defaultAllowed.credentials());
        filter.setCorsMaxAge(corsProperties.defaultMaxAge);

        filter.setCorsXhrAllowedUris(corsProperties.xhrAllowed.uris());
        filter.setCorsXhrAllowedOrigins(corsProperties.xhrAllowed.origins());
        filter.setCorsXhrAllowedHeaders(corsProperties.xhrAllowed.headers());
        filter.setCorsXhrAllowedMethods(corsProperties.xhrAllowed.methods());
        filter.setCorsXhrAllowedCredentials(corsProperties.xhrAllowed.credentials());
        filter.setCorsXhrMaxAge(corsProperties.xhrMaxAge);
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);

        filter.initialize();
        return bean;
    }

    @Bean
    FilterRegistrationBean<LimitedModeUaaFilter> limitedModeUaaFilter() {
        LimitedModeUaaFilter filter = new LimitedModeUaaFilter();
        filter.setStatusFile(limitedModeProperties.statusFile);
        filter.setPermittedEndpoints(limitedModeProperties.permitted.endpoints());
        filter.setPermittedMethods(limitedModeProperties.permitted.methods());
        FilterRegistrationBean<LimitedModeUaaFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<HeaderFilter> headerFilter(

    ) {
        HeaderFilter filter = new HeaderFilter(servletProps.filteredHeaders());
        FilterRegistrationBean<HeaderFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<ContentSecurityPolicyFilter> contentSecurityPolicyFilter() {
        ContentSecurityPolicyFilter filter = new ContentSecurityPolicyFilter(cspProps.scriptSrc());
        FilterRegistrationBean<ContentSecurityPolicyFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }



    @Bean
    FilterRegistrationBean<UaaMetricsFilter> metricsFilter(TimeService timeService) throws IOException {
        UaaMetricsFilter filter = new UaaMetricsFilter(metricsProps.enabled(), metricsProps.perRequestMetrics(), timeService);
        FilterRegistrationBean<UaaMetricsFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    UaaMetrics uaaMetrics(FilterRegistrationBean<UaaMetricsFilter> metricsFilter) {
        return new UaaMetricsManagedBean(metricsFilter.getFilter());
    }

    @Bean
    FilterRegistrationBean<DisableUserManagementSecurityFilter> userManagementSecurityFilter(
            @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning
    ) {
        DisableUserManagementSecurityFilter filter = new DisableUserManagementSecurityFilter(provisioning, identityZoneManager);
        FilterRegistrationBean<DisableUserManagementSecurityFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<DisableInternalUserManagementFilter> userManagementFilter(
            @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning
    ) {
        DisableInternalUserManagementFilter filter = new DisableInternalUserManagementFilter(provisioning, identityZoneManager);
        FilterRegistrationBean<DisableInternalUserManagementFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<IdentityZoneResolvingFilter> identityZoneResolvingFilter(IdentityZoneProvisioning provisioning) {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(provisioning);
        filter.setDefaultInternalHostnames(new HashSet<>(Arrays.asList(
                UaaUrlUtils.getHostForURI(uaaProps.url()),
                UaaUrlUtils.getHostForURI(loginProps.url()),
                "localhost"
        )));
        filter.setAdditionalInternalHostnames(zoneProps.internal().hostnames());
        FilterRegistrationBean<IdentityZoneResolvingFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<SessionResetFilter> sessionResetFilter(
            @Qualifier("userDatabase") UaaUserDatabase userDatabase
    ) {
        SessionResetFilter filter = new SessionResetFilter(
                new DefaultRedirectStrategy(),
                identityZoneManager,
                "/login",
                userDatabase
        );
        FilterRegistrationBean<SessionResetFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<IdentityZoneSwitchingFilter> identityZoneSwitchingFilter(IdentityZoneProvisioning provisioning) {
        IdentityZoneSwitchingFilter filter = new IdentityZoneSwitchingFilter(provisioning);
        FilterRegistrationBean<IdentityZoneSwitchingFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<RateLimitingFilter> rateLimitingFilter() throws ServletException {
        RateLimitingFilter filter = new RateLimitingFilter();
        FilterRegistrationBean<RateLimitingFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<RequestContextFilter> springRequestContextFilter() {
        RequestContextFilter filter = new RequestContextFilter();
        FilterRegistrationBean<RequestContextFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    public FilterRegistrationBean<HttpHeaderSecurityFilter> httpHeaderSecurityFilter() {
        HttpHeaderSecurityFilter filter = new HttpHeaderSecurityFilter();
        filter.setHstsEnabled(false);
        filter.setAntiClickJackingEnabled(false);
        filter.setBlockContentTypeSniffingEnabled(true);
        FilterRegistrationBean<HttpHeaderSecurityFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    public FilterRegistrationBean<jakarta.servlet.Filter> clientCertificateMapperFilter() {
        // ClientCertificateMapper is a package-private final class in
        // org.cloudfoundry.router.jakarta; its constructor is also package-private.
        // The library is designed for Spring Boot autoconfiguration or Servlet container
        // initializer use — direct instantiation from outside the package requires
        // reflection. setAccessible(true) is the only available mechanism.
        try {
            Class<?> mapperClass = Class.forName("org.cloudfoundry.router.jakarta.ClientCertificateMapper");
            java.lang.reflect.Constructor<?> ctor = mapperClass.getDeclaredConstructor();
            ctor.setAccessible(true);
            @SuppressWarnings("unchecked")
            FilterRegistrationBean<jakarta.servlet.Filter> bean =
                    new FilterRegistrationBean<>((jakarta.servlet.Filter) ctor.newInstance());
            bean.addUrlPatterns("/oauth/mtls/*");
            // Spring Boot registers its Security filter in the servlet container at order -100
            // (org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties
            // .DEFAULT_FILTER_ORDER). This filter must run strictly before that so the
            // jakarta.servlet.request.X509Certificate request attribute it derives from the
            // XFCC header is already populated when ClientDetailsAuthenticationProvider /
            // TlsClientAuthentication authenticate the /oauth/mtls/token request.
            bean.setOrder(-200);
            return bean;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to instantiate ClientCertificateMapper", e);
        }
    }
}
