package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class ExpressionHandlerBeanDefinitionParserTest {

    @Test
    void getBeanClass() {
        ExpressionHandlerBeanDefinitionParser expressionHandlerBeanDefinitionParser = new ExpressionHandlerBeanDefinitionParser();
        assertThat(expressionHandlerBeanDefinitionParser.getBeanClass(mock(Element.class))).isEqualTo(OAuth2MethodSecurityExpressionHandler.class);
    }
}
