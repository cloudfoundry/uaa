package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.oauth.ClientAccessTokenValidity;
import org.cloudfoundry.identity.uaa.oauth.ClientRefreshTokenValidity;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.security.web.TokenEndpointPostProcessor;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.xmlsec.signature.P;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OauthEndpointBeanConfiguration {

    @Autowired
    @Qualifier("jdbcClientDetailsService")
    MultitenantClientServices jdbcClientDetailsService;

    @Autowired
    @Qualifier("timeService")
    TimeService timeService;

    @Autowired
    @Qualifier("tokenEndpointBuilder")
    TokenEndpointBuilder tokenEndpointBuilder;

    @Autowired
    IdentityZoneManager identityZoneManager;
    @Bean
    UaaOauth2RequestValidator oauth2RequestValidator() {
        UaaOauth2RequestValidator bean = new UaaOauth2RequestValidator();
        bean.setClientDetailsService(jdbcClientDetailsService);
        return bean;
    }

    @Bean
    TokenEndpointPostProcessor tokenEndpointPostProcessor() {
        return new TokenEndpointPostProcessor();
    }

    @Bean
    ClientAccessTokenValidity clientAccessTokenValidity() {
        return new ClientAccessTokenValidity(jdbcClientDetailsService, identityZoneManager);
    }

    @Bean
    ClientRefreshTokenValidity clientRefreshTokenValidity() {
        return new ClientRefreshTokenValidity(jdbcClientDetailsService, identityZoneManager);
    }

    @Bean
    TokenValidityResolver accessTokenValidityResolver(
            @Autowired ClientAccessTokenValidity clientAccessTokenValidity,
            @Value("${jwt.token.policy.global.accessTokenValiditySeconds:43200}") int accessTokenValidity
    ) {
        return new TokenValidityResolver(
                clientAccessTokenValidity,
                accessTokenValidity,
                timeService
        );
    }


//    @Bean
//    UaaTokenServices tokenServices() {
//        <constructor-arg name="idTokenCreator" ref="idTokenCreator"/>
//        <constructor-arg name="tokenEndpointBuilder" ref="tokenEndpointBuilder"/>
//        <constructor-arg name="clientDetailsService" ref="jdbcClientDetailsService"/>
//        <constructor-arg name="revocableTokenProvisioning" ref="revocableTokenProvisioning"/>
//        <constructor-arg name="tokenValidationService" ref="tokenValidationService"/>
//        <constructor-arg name="refreshTokenCreator" ref="refreshTokenCreator"/>
//        <constructor-arg name="timeService" ref="timeService"/>
//        <constructor-arg name="accessTokenValidityResolver" ref="accessTokenValidityResolver"/>
//        <constructor-arg name="userDatabase" ref="userDatabase"/>
//        <constructor-arg name="approvalService" ref="approvalService"/>
//        <constructor-arg name="excludedClaims" ref="excludedClaims"/>
//        <constructor-arg name="globalTokenPolicy" ref="globalTokenPolicy"/>
//        <constructor-arg name="keyInfoService" ref="keyInfoService"/>
//        <constructor-arg name="idTokenGranter" ref="idTokenGranter"/>
//    }
}
