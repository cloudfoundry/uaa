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

import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderServerBeanConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.filter.CompositeFilter;

import static java.util.Arrays.asList;
import static org.cloudfoundry.identity.uaa.zone.IdentityZone.getUaa;

@Configuration
public class HostedSamlIdentityProviderConfiguration extends SamlIdentityProviderServerBeanConfiguration {

    private AuthenticationSuccessHandler successHandler;
    private UaaUserDatabase userDatabase;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private SamlServiceProviderProvisioning serviceProviderProvisioning;
    private IdentityZoneProvisioning zoneProvisioning;
    private JdbcScimUserProvisioning scimUserProvisioning;
    private FileIdentityProviderConfiguration fileIdpConfig;

    public HostedSamlIdentityProviderConfiguration(
        IdentityZoneProvisioning zoneProvisioning,
        @Qualifier("userDatabase") UaaUserDatabase userDb,
        @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning idpProvisioning,
        @Qualifier("serviceProviderProvisioning") SamlServiceProviderProvisioning serviceProviderProvisioning,
        @Qualifier("successRedirectHandler") AuthenticationSuccessHandler successHandler,
        @Qualifier("scimUserProvisioning") JdbcScimUserProvisioning scimUserProvisioning,
        @Qualifier("UaaIdpConfiguration") FileIdentityProviderConfiguration fileIdpConfig) {
        this.userDatabase = userDb;
        this.identityProviderProvisioning = idpProvisioning;
        this.serviceProviderProvisioning = serviceProviderProvisioning;
        this.successHandler = successHandler;
        this.zoneProvisioning = zoneProvisioning;
        this.scimUserProvisioning = scimUserProvisioning;
        this.fileIdpConfig = fileIdpConfig;
    }

    @Bean("idpSamlProviderConfigurationProvisioning")
    public SamlProviderConfigurationProvisioning getIdpSamlProviderConfigurationProvisioning() {
        return new SamlProviderConfigurationProvisioning(
            fileIdpConfig.getEntityId(),
            fileIdpConfig.getEntityAlias(),
            fileIdpConfig.getEntityBaseUrl(),
            fileIdpConfig.getSignatureAlgorithm(),
            fileIdpConfig.getSignatureDigest(),
            identityProviderProvisioning,
            serviceProviderProvisioning
        );
    }

    @Override
    @Bean("idpSamlConfigurationRepository")
    public SamlConfigurationRepository samlConfigurationRepository() {
        return new ThreadLocalSamlConfigurationRepository(
            getIdpSamlProviderConfigurationProvisioning()
        );
    }

    @Override
    @Bean(name = "samlIdentityProviderProvisioning")
    @DependsOn("identityZoneHolderInitializer")
    public SamlProviderProvisioning<IdentityProviderService> getSamlProvisioning() {
        return new SamlIdentityProviderCustomizer(
            samlConfigurationRepository(),
            samlTransformer(),
            samlValidator(),
            samlMetadataCache()
        );
    }

    @Override
    @Bean("idpSamlConfigurationFilter")
    public Filter samlConfigurationFilter() {
        return super.samlConfigurationFilter();
    }

    @Bean(name = "spMetaDataProviders")
    public SamlServiceProviderConfigurator samlIdentityProviderConfigurator() {
        SamlServiceProviderConfigurator result = new SamlServiceProviderConfigurator();
        result.setProviderProvisioning(serviceProviderProvisioning);
        result.setResolver(getSamlProvisioning());
        return result;
    }

    @Override
    @DependsOn("identityZoneConfigurationBootstrap")
    protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
        IdentityZone zone = zoneProvisioning.retrieve(getUaa().getId());
        return getIdpSamlProviderConfigurationProvisioning().getSamlServerConfiguration(zone);
    }

    @Override
    public Filter idpMetadataFilter() {
        return super.idpMetadataFilter();
    }

    @Override
    public Filter idpInitatedLoginFilter() {
        return new SamlIdpAuthenticationFilter(
            getSamlProvisioning(),
            samlAssertionStore(),
            new SamlRequestMatcher(getSamlProvisioning(), "init"),
            serviceProviderProvisioning,
            scimUserProvisioning,
            samlIdentityProviderConfigurator()
        );
    }

    public Filter idpUaaInitatedLoginFilter() {
        return new SamlIdpAuthenticationFilter(
            getSamlProvisioning(),
            samlAssertionStore(),
            new SamlRequestMatcher(getSamlProvisioning(), "initiate"),
            serviceProviderProvisioning,
            scimUserProvisioning,
            samlIdentityProviderConfigurator()
        );
    }

    @Override
    public Filter idpAuthnRequestFilter() {
        return new SamlIdpAuthenticationRequestFilter(
            getSamlProvisioning(),
            samlAssertionStore(),
            new SamlRequestMatcher(getSamlProvisioning(), "SSO"),
            serviceProviderProvisioning,
            scimUserProvisioning,
            samlIdentityProviderConfigurator()
        );
    }

    @Override
    public Filter idpLogoutFilter() {
        return super.idpLogoutFilter();
    }

    @Override
    public Filter idpSelectServiceProviderFilter() {
        return super.idpSelectServiceProviderFilter();
    }

    @Bean
    public Filter compositeIdpFilter() {
        CompositeFilter filter = new CompositeFilter();
        filter.setFilters(
            asList(
                new SamlExceptionFilter(),
                samlConfigurationFilter(),
                idpMetadataFilter(),
                idpUaaInitatedLoginFilter(),
                idpInitatedLoginFilter(),
                idpAuthnRequestFilter(),
                idpLogoutFilter(),
                idpSelectServiceProviderFilter()
            )
        );
        return filter;
    }
}
