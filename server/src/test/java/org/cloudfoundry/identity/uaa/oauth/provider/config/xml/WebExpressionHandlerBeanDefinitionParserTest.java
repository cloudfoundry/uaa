package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.junit.Test;
import org.w3c.dom.Element;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class WebExpressionHandlerBeanDefinitionParserTest {

    @Test
    public void getBeanClass() {
        WebExpressionHandlerBeanDefinitionParser parser = new WebExpressionHandlerBeanDefinitionParser();
        assertEquals(OAuth2WebSecurityExpressionHandler.class, parser.getBeanClass(mock(Element.class)));
    }
}
