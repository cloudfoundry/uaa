package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.provider.client.OAuth2ClientContextFilter;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Moved class ClientBeanDefinitionParser implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server setup in xml
 */
public class ClientBeanDefinitionParser extends AbstractBeanDefinitionParser {

    @Override
    protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

        String redirectStrategyRef = element.getAttribute("redirect-strategy-ref");

        BeanDefinitionBuilder clientContextFilterBean = BeanDefinitionBuilder
                .rootBeanDefinition(OAuth2ClientContextFilter.class);

        if (StringUtils.hasText(redirectStrategyRef)) {
            clientContextFilterBean.addPropertyReference("redirectStrategy", redirectStrategyRef);
        }

        return clientContextFilterBean.getBeanDefinition();

    }

}
