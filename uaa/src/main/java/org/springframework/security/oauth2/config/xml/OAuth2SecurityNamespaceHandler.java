package org.springframework.security.oauth2.config.xml;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

public class OAuth2SecurityNamespaceHandler extends NamespaceHandlerSupport {

	public void init() {
		registerBeanDefinitionParser("authorization-server", new AuthorizationServerBeanDefinitionParser());
		registerBeanDefinitionParser("resource-server", new ResourceServerBeanDefinitionParser());
		registerBeanDefinitionParser("client-details-service", new ClientDetailsServiceBeanDefinitionParser());
		registerBeanDefinitionParser("client", new ClientBeanDefinitionParser());
		registerBeanDefinitionParser("resource", new ResourceBeanDefinitionParser());
		registerBeanDefinitionParser("rest-template", new RestTemplateBeanDefinitionParser());
		registerBeanDefinitionParser("expression-handler", new ExpressionHandlerBeanDefinitionParser());
		registerBeanDefinitionParser("web-expression-handler", new WebExpressionHandlerBeanDefinitionParser());
	}
}
