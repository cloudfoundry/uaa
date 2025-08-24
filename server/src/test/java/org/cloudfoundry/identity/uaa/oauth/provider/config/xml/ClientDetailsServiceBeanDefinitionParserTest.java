package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.client.InMemoryClientDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.XmlReaderContext;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class ClientDetailsServiceBeanDefinitionParserTest {

    private ClientDetailsServiceBeanDefinitionParser parser;
    private Element element;
    private Element clientElement = mock(Element.class);
    private ParserContext parserContext;
    BeanDefinitionBuilder builder;
    NodeList nodeList;
    private XmlReaderContext xmlReaderContext;

    @BeforeEach
    void setup() {
        parser = new ClientDetailsServiceBeanDefinitionParser();
        element = mock(Element.class);
        clientElement = mock(Element.class);
        builder = mock(BeanDefinitionBuilder.class);
        parserContext = mock(ParserContext.class);
        nodeList = mock(NodeList.class);
        xmlReaderContext = mock(XmlReaderContext.class);
        when(parserContext.getReaderContext()).thenReturn(xmlReaderContext);
        when(parserContext.getRegistry()).thenReturn(mock(BeanDefinitionRegistry.class));
        when(element.getChildNodes()).thenReturn(nodeList);
    }

    @Test
    void getBeanClass() {
        assertThat(parser.getBeanClass(element)).isEqualTo(InMemoryClientDetailsService.class);
    }

    @Test
    void doParseNothing() {
        when(nodeList.getLength()).thenReturn(0);
        parser.doParse(element, parserContext, builder);
        verify(builder, times(1)).addPropertyValue(anyString(), any(Object.class));
    }

    @Test
    void doParseNoClientId() {
        when(nodeList.getLength()).thenReturn(1);
        when(nodeList.item(0)).thenReturn(clientElement);
        when(clientElement.getNodeName()).thenReturn("client");
        when(clientElement.getAttribute("client-id")).thenReturn(null);
        parser.doParse(element, parserContext, builder);
        verify(builder, times(1)).addPropertyValue(anyString(), any(Object.class));
        verify(xmlReaderContext).error("A client id must be supplied with the definition of a client.", clientElement);
    }

    @Test
    void doParseClientAttributes() {
        when(nodeList.getLength()).thenReturn(1);
        when(nodeList.item(0)).thenReturn(clientElement);
        when(clientElement.getNodeName()).thenReturn("client");
        when(clientElement.getAttribute("client-id")).thenReturn("client-id");
        when(clientElement.getAttribute("secret")).thenReturn("secret");
        when(clientElement.getAttribute("access-token-validity")).thenReturn("access-token-validity");
        when(clientElement.getAttribute("refresh-token-validity")).thenReturn("refresh-token-validity");
        when(clientElement.getAttribute("redirect-uri")).thenReturn("redirect-uri");
        parser.doParse(element, parserContext, builder);
        verify(builder, times(1)).addPropertyValue(anyString(), any(Object.class));
        verify(xmlReaderContext, never()).error("A client id must be supplied with the definition of a client.", clientElement);
    }
}
