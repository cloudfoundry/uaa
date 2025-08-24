package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.XmlReaderContext;
import org.w3c.dom.Element;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class ProviderBeanDefinitionParserTest {

    private ProviderBeanDefinitionParser parser;
    private Element element;
    private ParserContext parserContext;
    private XmlReaderContext xmlReaderContext;

    @BeforeEach
    void setUp() throws Exception {
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
    void parseInternal() {
        assertThat(parser.parseInternal(element, parserContext)).isNotNull();
        when(element.getAttribute("token-services-ref")).thenReturn("token-services-ref");
        assertThat(parser.parseInternal(element, parserContext)).isNotNull();
    }

    @Test
    void parseEndpointAndReturnFilter() {
        assertThat(parser.parseEndpointAndReturnFilter(element, parserContext, "tokenServicesRef", "serializerRef")).isNotNull();
    }
}
