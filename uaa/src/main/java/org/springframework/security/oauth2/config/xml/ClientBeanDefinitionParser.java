package org.springframework.security.oauth2.config.xml;

import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;


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
