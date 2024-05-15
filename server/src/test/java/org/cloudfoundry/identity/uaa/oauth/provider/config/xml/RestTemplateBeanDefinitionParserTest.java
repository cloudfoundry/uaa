package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.xml.BeanDefinitionParserDelegate;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.XmlReaderContext;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class RestTemplateBeanDefinitionParserTest {

  private RestTemplateBeanDefinitionParser parser;
  private Element element;
  private BeanDefinitionBuilder builder;
  private ParserContext parserContext;
  private XmlReaderContext xmlReaderContext;

  @Before
  public void setUp() throws Exception {
    element = mock(Element.class);
    parserContext = mock(ParserContext.class);
    xmlReaderContext = mock(XmlReaderContext.class);
    builder = mock(BeanDefinitionBuilder.class);
    when(parserContext.getReaderContext()).thenReturn(xmlReaderContext);
    when(parserContext.getRegistry()).thenReturn(mock(BeanDefinitionRegistry.class));
    when(xmlReaderContext.generateBeanName(any(BeanDefinition.class))).thenReturn("bean");//thenAnswer(invocation -> invocation.getArguments()[0]);
    parser = new RestTemplateBeanDefinitionParser();
  }

  @Test
  public void getBeanClass() {
    assertEquals(OAuth2RestTemplate.class, parser.getBeanClass(element));
  }

  @Test
  public void doParse() {
    when(element.getAttribute("access-token-provider")).thenReturn("ref");
    when(element.getAttribute("resource")).thenReturn("classpath:oauth-rest-template.xml");
    when(parserContext.getDelegate()).thenReturn(new BeanDefinitionParserDelegate(xmlReaderContext));
    when(element.getChildNodes()).thenReturn(mock(NodeList.class));
    parser.doParse(element, parserContext, builder);
    verify(builder, times(1)).addConstructorArgReference("classpath:oauth-rest-template.xml");
  }
}
