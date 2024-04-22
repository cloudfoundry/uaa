package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.junit.Test;
import org.w3c.dom.Element;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ExpressionHandlerBeanDefinitionParserTest {

  @Test
  public void getBeanClass() {
    ExpressionHandlerBeanDefinitionParser expressionHandlerBeanDefinitionParser = new ExpressionHandlerBeanDefinitionParser();
    assertEquals(OAuth2MethodSecurityExpressionHandler.class, expressionHandlerBeanDefinitionParser.getBeanClass(mock(Element.class)));
  }
}
