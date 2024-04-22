package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.XmlReaderContext;
import org.w3c.dom.Element;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ProviderBeanDefinitionParserTest {

  private ProviderBeanDefinitionParser parser;
  private Element element;
  private ParserContext parserContext;
  private XmlReaderContext xmlReaderContext;

  @Before
  public void setUp() throws Exception {
    element = mock(Element.class);
    parserContext = mock(ParserContext.class);
    xmlReaderContext = mock(XmlReaderContext.class);
    when(parserContext.getReaderContext()).thenReturn(xmlReaderContext);
    when(parserContext.getRegistry()).thenReturn(mock(BeanDefinitionRegistry.class));
    parser = new ProviderBeanDefinitionParser() {
      @Override
      protected AbstractBeanDefinition parseEndpointAndReturnFilter(Element element, ParserContext parserContext, String tokenServicesRef,
          String serializerRef) {
        return mock(AbstractBeanDefinition.class);
      }
    };
  }

  @Test
  public void parseInternal() {
    assertNotNull(parser.parseInternal(element, parserContext));
    when(element.getAttribute("token-services-ref")).thenReturn("token-services-ref");
    assertNotNull(parser.parseInternal(element, parserContext));
  }

  @Test
  public void parseEndpointAndReturnFilter() {
    assertNotNull(parser.parseEndpointAndReturnFilter(element, parserContext, "tokenServicesRef", "serializerRef"));
  }
}
