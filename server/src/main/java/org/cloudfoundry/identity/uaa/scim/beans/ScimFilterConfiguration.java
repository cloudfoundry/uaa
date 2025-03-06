package org.cloudfoundry.identity.uaa.scim.beans;

import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class ScimFilterConfiguration {

    @Autowired
    @Qualifier("tokenServices")
    private UaaTokenServices tokenServices;

    @Autowired()
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint entryPoint;

    @Bean
    OAuth2AuthenticationProcessingFilter passwordResourceAuthenticationFilter() {
        OAuth2AuthenticationProcessingFilter bean = new OAuth2AuthenticationProcessingFilter();
        bean.setAuthenticationManager(getoAuth2AuthenticationManager(tokenServices, "password"));
        bean.setAuthenticationEntryPoint(entryPoint);
        return bean;
    }

    @Bean
    OAuth2AuthenticationProcessingFilter scimResourceAuthenticationFilter() {
        OAuth2AuthenticationProcessingFilter bean = new OAuth2AuthenticationProcessingFilter();
        bean.setAuthenticationManager(getoAuth2AuthenticationManager(tokenServices, "scim"));
        bean.setAuthenticationEntryPoint(entryPoint);
        return bean;
    }

    @Bean
    OAuth2AuthenticationProcessingFilter resourceAgnosticAuthenticationFilter() {
        OAuth2AuthenticationProcessingFilter bean = new OAuth2AuthenticationProcessingFilter();
        bean.setAuthenticationManager(getoAuth2AuthenticationManager(tokenServices, null));
        bean.setAuthenticationEntryPoint(entryPoint);
        return bean;
    }


    private static OAuth2AuthenticationManager getoAuth2AuthenticationManager(
            UaaTokenServices tokenServices,
            String resourceId
    ) {
        OAuth2AuthenticationManager authenticationManager = new OAuth2AuthenticationManager();
        authenticationManager.setTokenServices(tokenServices);
        authenticationManager.setResourceId(resourceId);
        return authenticationManager;
    }


}
