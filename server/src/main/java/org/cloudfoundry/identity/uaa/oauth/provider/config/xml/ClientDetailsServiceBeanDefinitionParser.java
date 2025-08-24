package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.client.InMemoryClientDetailsService;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.util.List;

/**
 * Moved class ClientDetailsServiceBeanDefinitionParser implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server setup in xml
 */
public class ClientDetailsServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    @Override
    protected Class<?> getBeanClass(Element element) {
        return InMemoryClientDetailsService.class;
    }

    @Override
    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        List<Element> clientElements = DomUtils.getChildElementsByTagName(element, "client");
        ManagedMap<String, BeanMetadataElement> clients = new ManagedMap<>();
        for (Element clientElement : clientElements) {
            BeanDefinitionBuilder client = BeanDefinitionBuilder.rootBeanDefinition(UaaClientDetails.class);
            String clientId = clientElement.getAttribute("client-id");
            if (StringUtils.hasText(clientId)) {
                client.addConstructorArgValue(clientId);
            } else {
                parserContext.getReaderContext().error("A client id must be supplied with the definition of a client.",
                        clientElement);
            }

            String secret = clientElement.getAttribute("secret");
            if (StringUtils.hasText(secret)) {
                client.addPropertyValue("clientSecret", secret);
            }
            String resourceIds = clientElement.getAttribute("resource-ids");
            if (StringUtils.hasText(clientId)) {
                client.addConstructorArgValue(resourceIds);
            } else {
                client.addConstructorArgValue("");
            }
            String redirectUri = clientElement.getAttribute("redirect-uri");
            String tokenValidity = clientElement.getAttribute("access-token-validity");
            if (StringUtils.hasText(tokenValidity)) {
                client.addPropertyValue("accessTokenValiditySeconds", tokenValidity);
            }
            String refreshValidity = clientElement.getAttribute("refresh-token-validity");
            if (StringUtils.hasText(refreshValidity)) {
                client.addPropertyValue("refreshTokenValiditySeconds", refreshValidity);
            }
            client.addConstructorArgValue(clientElement.getAttribute("scope"));
            client.addConstructorArgValue(clientElement.getAttribute("authorized-grant-types"));
            client.addConstructorArgValue(clientElement.getAttribute("authorities"));
            if (StringUtils.hasText(redirectUri)) {
                client.addConstructorArgValue(redirectUri);
            }
            client.addPropertyValue("autoApproveScopes", clientElement.getAttribute("autoapprove"));

            clients.put(clientId, client.getBeanDefinition());
        }

        builder.addPropertyValue("clientDetailsStore", clients);
    }
}