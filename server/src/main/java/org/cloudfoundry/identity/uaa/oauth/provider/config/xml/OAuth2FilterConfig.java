package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.authentication.BackwardsCompatibleTokenEndpointAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.manager.PasswordGrantAuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.provider.CompositeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.JwtTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.token.PkceEnhancedAuthorizationCodeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.Saml2TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.token.UserTokenGranter;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.saml.Saml2BearerGrantAuthenticationConverter;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.AuthenticationEntryPoint;
import javax.servlet.http.HttpServletRequest;

@Configuration
public class OAuth2FilterConfig {

    @Autowired
    @Bean
    BackwardsCompatibleTokenEndpointAuthenticationFilter tokenEndpointAuthenticationFilter(PasswordGrantAuthenticationManager passwordGrantAuthenticationManager,
            UaaAuthorizationRequestManager authorizationRequestManager,
            Saml2BearerGrantAuthenticationConverter samlBearerGrantAuthenticationProvider,
            ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager,
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
            AuthenticationEntryPoint basicAuthenticationEntryPoint) {

        BackwardsCompatibleTokenEndpointAuthenticationFilter authenticationFilter =
                new BackwardsCompatibleTokenEndpointAuthenticationFilter("/oauth/token/alias/{registrationId}",
                        passwordGrantAuthenticationManager, authorizationRequestManager, samlBearerGrantAuthenticationProvider,
                        externalOAuthAuthenticationManager);
        authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        authenticationFilter.setAuthenticationEntryPoint(basicAuthenticationEntryPoint);

        return authenticationFilter;
    }

    @Autowired
    @Bean
    public PkceEnhancedAuthorizationCodeTokenGranter pkceEnhancedAuthorizationCodeTokenGranter(@Qualifier("oauth2TokenGranter") CompositeTokenGranter compositeTokenGranter,
            @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices,
            @Qualifier("authorizationCodeServices") AuthorizationCodeServices authorizationCodeServices,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory requestFactory,
            @Qualifier("pkceValidationServices") PkceValidationService pkceValidationServices) {
        PkceEnhancedAuthorizationCodeTokenGranter tokenGranter = new PkceEnhancedAuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices, clientDetailsService, requestFactory);
        tokenGranter.setPkceValidationService(pkceValidationServices);
        compositeTokenGranter.addTokenGranter(tokenGranter);

        return tokenGranter;
    }

    @Autowired
    @Bean
    public UserTokenGranter userTokenGranter(@Qualifier("oauth2TokenGranter") CompositeTokenGranter compositeTokenGranter,
            @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory requestFactory,
            @Qualifier("revocableTokenProvisioning") RevocableTokenProvisioning tokenStore) {
        UserTokenGranter tokenGranter = new UserTokenGranter(tokenServices, clientDetailsService, requestFactory, tokenStore);
        compositeTokenGranter.addTokenGranter(tokenGranter);

        return tokenGranter;
    }

    @Autowired
    @Bean
    public JwtTokenGranter jwtTokenGranter(@Qualifier("oauth2TokenGranter") CompositeTokenGranter compositeTokenGranter,
            @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory requestFactory) {
        JwtTokenGranter tokenGranter = new JwtTokenGranter(tokenServices, clientDetailsService, requestFactory);
        compositeTokenGranter.addTokenGranter(tokenGranter);

        return tokenGranter;
    }

    @Autowired
    @Bean
    public Saml2TokenGranter samlTokenGranter(@Qualifier("oauth2TokenGranter") CompositeTokenGranter compositeTokenGranter,
            @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory requestFactory,
            SecurityContextAccessor securityContextAccessor) {
        Saml2TokenGranter tokenGranter = new Saml2TokenGranter(tokenServices, clientDetailsService, requestFactory, securityContextAccessor);
        compositeTokenGranter.addTokenGranter(tokenGranter);

        return tokenGranter;
    }
}
