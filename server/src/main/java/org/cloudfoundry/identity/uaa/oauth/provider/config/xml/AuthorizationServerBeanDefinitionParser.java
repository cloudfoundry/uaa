package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.CheckTokenEndpoint;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.CompositeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.approval.DefaultUserApprovalHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.client.ClientCredentialsTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.code.InMemoryAuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.WhitelabelApprovalEndpoint;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.password.ResourceOwnerPasswordTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.refresh.RefreshTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenEndpoint;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.config.TypedStringValue;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.util.List;

/**
 * Moved class AuthorizationServerBeanDefinitionParser implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server setup in xml
 */
public class AuthorizationServerBeanDefinitionParser
        extends ProviderBeanDefinitionParser {

    @Override
    protected AbstractBeanDefinition parseEndpointAndReturnFilter(Element element,
            ParserContext parserContext, String tokenServicesRef, String serializerRef) {

        // We aren't defining a filter...
        //no op now
        return null;

    }

}
