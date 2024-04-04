package org.springframework.security.oauth2.config.xml;

import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.w3c.dom.Element;

public class WebExpressionHandlerBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

	@Override
	protected Class<?> getBeanClass(Element element) {
		return OAuth2WebSecurityExpressionHandler.class;
	}

}