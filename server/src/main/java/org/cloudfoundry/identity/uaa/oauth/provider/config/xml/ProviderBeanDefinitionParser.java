package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.provider.token.DefaultTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.InMemoryTokenStore;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Moved class ProviderBeanDefinitionParser implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server setup in xml
 */
public abstract class ProviderBeanDefinitionParser extends AbstractBeanDefinitionParser {

    @Override
    protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

        String tokenServicesRef = element.getAttribute("token-services-ref");
        String serializerRef = element.getAttribute("serialization-service-ref");

        if (!StringUtils.hasText(tokenServicesRef)) {
            tokenServicesRef = "oauth2TokenServices";
            BeanDefinitionBuilder tokenServices = BeanDefinitionBuilder.rootBeanDefinition(DefaultTokenServices.class);
            AbstractBeanDefinition tokenStore = BeanDefinitionBuilder.rootBeanDefinition(InMemoryTokenStore.class).getBeanDefinition();
            tokenServices.addPropertyValue("tokenStore", tokenStore);
            parserContext.getRegistry().registerBeanDefinition(tokenServicesRef, tokenServices.getBeanDefinition());
        }

        return parseEndpointAndReturnFilter(element, parserContext, tokenServicesRef, serializerRef);
    }

    protected abstract AbstractBeanDefinition parseEndpointAndReturnFilter(Element element, ParserContext parserContext,
            String tokenServicesRef, String serializerRef);

}
