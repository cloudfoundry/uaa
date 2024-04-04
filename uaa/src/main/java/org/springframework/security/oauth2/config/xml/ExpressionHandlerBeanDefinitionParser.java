package org.springframework.security.oauth2.config.xml;

import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.w3c.dom.Element;

public class ExpressionHandlerBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

	@Override
	protected Class<?> getBeanClass(Element element) {
		return OAuth2MethodSecurityExpressionHandler.class;
	}

}