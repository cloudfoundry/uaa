package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class ClientBeanDefinitionParserTest {

    @Test
    void parseInternal() {
        Element element = mock(Element.class);
        ParserContext parserContext = mock(ParserContext.class);
        ClientBeanDefinitionParser parser = new ClientBeanDefinitionParser();
        when(element.getAttribute("redirect-strategy-ref")).thenReturn("client_id");
        assertThat(parser.parseInternal(element, parserContext)).isNotNull();
    }
}
