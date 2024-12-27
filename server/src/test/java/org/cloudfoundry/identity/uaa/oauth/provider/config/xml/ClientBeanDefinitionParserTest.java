package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.junit.Test;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ClientBeanDefinitionParserTest {

    private ClientBeanDefinitionParser parser;
    private Element element;
    private ParserContext parserContext;

    @Test
    public void parseInternal() {
        element = mock(Element.class);
        parserContext = mock(ParserContext.class);
        parser = new ClientBeanDefinitionParser();
        when(element.getAttribute("redirect-strategy-ref")).thenReturn("client_id");
        assertNotNull(parser.parseInternal(element, parserContext));
    }
}
