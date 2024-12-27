package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.junit.Before;
import org.junit.Test;
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
public class ResourceServerBeanDefinitionParserTest {

    private ResourceServerBeanDefinitionParser parser;
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
        parser = new ResourceServerBeanDefinitionParser();
    }

    @Test
    public void parseEndpointAndReturnFilter() {
        assertNotNull(parser.parseEndpointAndReturnFilter(element, parserContext, "tokenServiceRef", "serialRef"));
    }

    @Test
    public void parseEndpointAndReturnFilterAuthRef() {
        when(element.getAttribute("authentication-manager-ref")).thenReturn("ref");
        assertNotNull(parser.parseEndpointAndReturnFilter(element, parserContext, "tokenServiceRef", "serialRef"));
    }

    @Test
    public void parseEndpointAndReturnFilterAttributes() {
        when(element.getAttribute("resource-id")).thenReturn("resource-id");
        when(element.getAttribute("entry-point-ref")).thenReturn("entry-point-ref");
        when(element.getAttribute("authentication-manager-ref")).thenReturn(null);
        when(element.getAttribute("token-extractor-ref")).thenReturn("token-extractor-ref");
        when(element.getAttribute("auth-details-source-ref")).thenReturn("auth-details-source-ref");
        when(element.getAttribute("stateless")).thenReturn("true");
        assertNotNull(parser.parseEndpointAndReturnFilter(element, parserContext, "tokenServiceRef", "serialRef"));
    }
}
