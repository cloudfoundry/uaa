package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * Moved class OAuth2SecurityNamespaceHandler implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server setup in xml
 */
public class OAuth2SecurityNamespaceHandler extends NamespaceHandlerSupport {

    public void init() {
        registerBeanDefinitionParser("resource-server", new ResourceServerBeanDefinitionParser());
        registerBeanDefinitionParser("client", new ClientBeanDefinitionParser());
        registerBeanDefinitionParser("resource", new ResourceBeanDefinitionParser());
        registerBeanDefinitionParser("rest-template", new RestTemplateBeanDefinitionParser());
        registerBeanDefinitionParser("expression-handler", new ExpressionHandlerBeanDefinitionParser());
        registerBeanDefinitionParser("web-expression-handler", new WebExpressionHandlerBeanDefinitionParser());
    }
}
