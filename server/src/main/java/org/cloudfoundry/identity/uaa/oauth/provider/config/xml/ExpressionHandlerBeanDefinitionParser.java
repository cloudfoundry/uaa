package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.w3c.dom.Element;

/**
 * Moved class ExpressionHandlerBeanDefinitionParser implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server setup in xml
 */
public class ExpressionHandlerBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    @Override
    protected Class<?> getBeanClass(Element element) {
        return OAuth2MethodSecurityExpressionHandler.class;
    }

}