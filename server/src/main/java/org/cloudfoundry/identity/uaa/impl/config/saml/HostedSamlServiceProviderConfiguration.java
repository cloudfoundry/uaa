/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.impl.config.saml;

import javax.servlet.Filter;
import java.util.List;

import org.cloudfoundry.identity.uaa.authentication.SamlRedirectLogoutHandler;
import org.cloudfoundry.identity.uaa.authentication.UaaSamlLogoutFilter;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSAMLAuthenticationFailureHandler;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationProvider;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlProviderLogoutFilter;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.authentication.SamlResponseAuthenticationFilter;
import org.springframework.security.saml.provider.service.authentication.ServiceProviderLogoutHandler;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderServerBeanConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.filter.CompositeFilter;

import static java.util.Arrays.asList;

@Configuration
@DependsOn("identityZoneHolderInitializer")
public class HostedSamlServiceProviderConfiguration extends SamlServiceProviderServerBeanConfiguration
    implements InitializingBean {

    private AuthenticationSuccessHandler successHandler;
    private UaaUserDatabase userDatabase;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private SamlServiceProviderProvisioning serviceProviderProvisioning;
    private ScimGroupExternalMembershipManager externalMembershipManager;
    private LogoutSuccessHandler mainLogoutHandler;
    private LogoutHandler uaaAuthenticationFailureHandler;
    private IdentityZoneProvisioning zoneProvisioning;
    private FileServiceProviderConfiguration fileSpConfig;
    private SamlServerConfiguration defaultConfig = null;

    public HostedSamlServiceProviderConfiguration(
        IdentityZoneProvisioning zoneProvisioning,
        @Qualifier("userDatabase") UaaUserDatabase userDb,
        @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning idpProvisioning,
        @Qualifier("serviceProviderProvisioning") SamlServiceProviderProvisioning serviceProviderProvisioning,
        @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager extMbrManager,
        @Qualifier("successRedirectHandler") AuthenticationSuccessHandler successHandler,
        @Qualifier("logoutHandler") LogoutSuccessHandler logoutHandler,
        @Qualifier("uaaAuthenticationFailureHandler") LogoutHandler uaaAuthenticationFailureHandler,
        @Qualifier("UaaSpConfiguration") FileServiceProviderConfiguration fileSpConfig) {
        this.userDatabase = userDb;
        this.identityProviderProvisioning = idpProvisioning;
        this.serviceProviderProvisioning = serviceProviderProvisioning;
        this.externalMembershipManager = extMbrManager;
        this.successHandler = successHandler;
        this.mainLogoutHandler = logoutHandler;
        this.uaaAuthenticationFailureHandler = uaaAuthenticationFailureHandler;
        this.zoneProvisioning = zoneProvisioning;
        this.fileSpConfig = fileSpConfig;
    }

    @Override
    protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
        return defaultConfig;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        IdentityZone zone = zoneProvisioning.retrieve(IdentityZone.getUaa().getId());
        defaultConfig = getSpSamlProviderConfigurationProvisioning().getSamlServerConfiguration(zone);
    }

    @Override
    @Bean("spSamlConfigurationRepository")
    public SamlConfigurationRepository samlConfigurationRepository() {
        return new ThreadLocalSamlConfigurationRepository(
            getSpSamlProviderConfigurationProvisioning()
        );
    }

    @Override
    @Bean(name = "samlServiceProviderProvisioning")
    @DependsOn("identityZoneHolderInitializer")
    public SamlProviderProvisioning<ServiceProviderService> getSamlProvisioning() {
        return new SamlServiceProviderCustomizer(
            samlConfigurationRepository(),
            samlTransformer(),
            samlValidator(),
            samlMetadataCache()
        );
    }

    @Bean("spSamlProviderConfigurationProvisioning")
    @DependsOn("identityZoneHolderInitializer")
    public SamlProviderConfigurationProvisioning getSpSamlProviderConfigurationProvisioning() {
        return new SamlProviderConfigurationProvisioning(
            fileSpConfig.getEntityId(),
            fileSpConfig.getEntityAlias(),
            fileSpConfig.getEntityBaseUrl(),
            fileSpConfig.getSignatureAlgorithm(),
            fileSpConfig.getSignatureDigest(),
            identityProviderProvisioning,
            serviceProviderProvisioning
        );
    }

    @Override
    @Bean("spSamlConfigurationFilter")
    public Filter samlConfigurationFilter() {
        return super.samlConfigurationFilter();
    }

    @Override
    public Filter spAuthenticationResponseFilter() {
        SamlResponseAuthenticationFilter filter =
            (SamlResponseAuthenticationFilter) super.spAuthenticationResponseFilter();
        filter.setAuthenticationManager(samlAuthenticationManager());
        filter.setAuthenticationFailureHandler(loginSAMLAuthenticationFailureHandler());
        filter.setAuthenticationSuccessHandler(successHandler);
        return filter;
    }

    @Bean(name = "samlLogoutHandler")
    public LogoutHandler logoutHandler() {
        return samlLogoutHandler();
    }

    @Bean(name = "samlAuthenticationProvider")
    public LoginSamlAuthenticationProvider samlAuthenticationManager() {
        LoginSamlAuthenticationProvider result = new LoginSamlAuthenticationProvider();
        result.setUserDatabase(userDatabase);
        result.setIdentityProviderProvisioning(identityProviderProvisioning);
        result.setExternalMembershipManager(externalMembershipManager);
        result.setResolver(getSamlProvisioning());
        return result;
    }

    @Bean(name = "idpProviders")
    public SamlIdentityProviderConfigurator idpProviders() {
        return samlIdentityProviderConfigurator();
    }

    @Bean(name = "metaDataProviders")
    public SamlIdentityProviderConfigurator samlIdentityProviderConfigurator() {
        SamlIdentityProviderConfigurator result = new SamlIdentityProviderConfigurator();
        result.setIdentityProviderProvisioning(identityProviderProvisioning);
        result.setResolver(getSamlProvisioning());
        return result;
    }

    @Bean(name = "samlWhitelistLogoutHandler")
    public LogoutSuccessHandler samlWhitelistLogoutHandler() {
        return new SamlRedirectLogoutHandler(mainLogoutHandler);
    }



    @Bean(name = "samlLogoutFilter")
    public Filter samlLogoutFilter() {
        return new UaaSamlLogoutFilter(samlWhitelistLogoutHandler(),
                                       uaaAuthenticationFailureHandler,
                                       samlLogoutHandler(),
                                       getSimpleSpLogoutHandler()
        );
    }

    public SimpleSpLogoutHandler getSimpleSpLogoutHandler() {
        return new SimpleSpLogoutHandler(
            getSamlProvisioning(),
            samlTransformer()
        );
    }

    public SecurityContextLogoutHandler samlLogoutHandler() {
        SecurityContextLogoutHandler handler = new SecurityContextLogoutHandler();
        handler.setInvalidateHttpSession(true);
        return handler;
    }

    @Bean(name = "samlLoginFailureHandler")
    public LoginSAMLAuthenticationFailureHandler loginSAMLAuthenticationFailureHandler() {
        LoginSAMLAuthenticationFailureHandler result = new LoginSAMLAuthenticationFailureHandler();
        result.setDefaultFailureUrl("/saml_error");
        return result;
    }

    @Bean(name = "assertionAuthenticationHandler")
    public SamlAssertionAuthenticationHandler assertionAuthenticationHandler() {
        return new SamlAssertionAuthenticationHandler(
            samlValidator(),
            getSamlProvisioning(),
            samlAuthenticationManager()
        );
    }

    @Override
    public Filter spMetadataFilter() {
        return super.spMetadataFilter();
    }

    @Override
    public Filter spAuthenticationRequestFilter() {
        return new SamlAuthenticationRequestFilter(getSamlProvisioning()) {
            @Override
            protected IdentityProviderMetadata getIdentityProvider(ServiceProviderService provider, String idpIdentifier) {
                String alias = idpIdentifier;
                List<IdentityProviderMetadata> providers = provider.getRemoteProviders();
                for (IdentityProviderMetadata idp : providers) {
                    if (alias.equals(idp.getEntityAlias())) {
                        return idp;
                    }
                }
                return super.getIdentityProvider(provider, idpIdentifier);
            }
        };
    }

    @Override
    public Filter spSamlLogoutFilter() {
        return new SamlProviderLogoutFilter<>(
            getSamlProvisioning(),
            new ServiceProviderLogoutHandler(getSamlProvisioning()),
            new SamlRequestMatcher(getSamlProvisioning(), "SingleLogout"),
            samlWhitelistLogoutHandler(),
            samlLogoutHandler()
        );
    }

    @Bean
    public Filter compositeSpFilter() {
        CompositeFilter filter = new CompositeFilter();
        filter.setFilters(
            asList(
                samlConfigurationFilter(),
                spMetadataFilter(),
                spAuthenticationRequestFilter(),
                spAuthenticationResponseFilter(),
                spSamlLogoutFilter()
            )
        );
        return filter;
    }

}
