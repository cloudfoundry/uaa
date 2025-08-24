package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.authentication.manager.CompositeAuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.CompositeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.client.ClientCredentialsTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.password.ResourceOwnerPasswordTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.refresh.RefreshTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static java.util.Arrays.asList;

/**
 * Replaces AuthorizationServerBeanDefinitionParser which parses <authorization-server> in oauth-endpoints.xml
 */
@Configuration
class AuthorizationServerBeanConfiguration {

    //oauth2ApprovalEndpoint - class WhitelabelApprovalEndpoint is automatically registered, we skip it here
    //uaaAuthorizationEndpoint - class UaaAuthorizationEndpoint is automatically registered, we skip it here
    //uaaTokenEndpoint - class UaaTokenEndpoint is automatically registered, we skip it here

    @Bean("oauth2TokenGranter")
    CompositeTokenGranter oauth2TokenGranter(
          @Qualifier("compositeAuthenticationManager") CompositeAuthenticationManager compositeAuthenticationManager,
          @Qualifier("tokenServices") AuthorizationServerTokenServices uaaTokenServices,
          @Qualifier("jdbcClientDetailsService") ClientDetailsService multiTenantJdbcClientDetailsServices,
          @Qualifier("authorizationRequestManager") OAuth2RequestFactory uaaAuthorizationRequestManager) {
        return new CompositeTokenGranter(asList(
                new RefreshTokenGranter(uaaTokenServices, multiTenantJdbcClientDetailsServices, uaaAuthorizationRequestManager),
                new ImplicitTokenGranter(uaaTokenServices, multiTenantJdbcClientDetailsServices, uaaAuthorizationRequestManager),
                new ClientCredentialsTokenGranter(uaaTokenServices, multiTenantJdbcClientDetailsServices, uaaAuthorizationRequestManager),
                new ResourceOwnerPasswordTokenGranter(compositeAuthenticationManager, uaaTokenServices, multiTenantJdbcClientDetailsServices, uaaAuthorizationRequestManager)
        ));
    }
}
