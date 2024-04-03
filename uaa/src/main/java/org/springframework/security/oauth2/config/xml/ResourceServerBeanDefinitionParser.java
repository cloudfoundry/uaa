package org.springframework.security.oauth2.config.xml;

import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

public class ResourceServerBeanDefinitionParser extends ProviderBeanDefinitionParser {

	@Override
	protected AbstractBeanDefinition parseEndpointAndReturnFilter(Element element, ParserContext parserContext,
			String tokenServicesRef, String serializerRef) {

		String resourceId = element.getAttribute("resource-id");
		String entryPointRef = element.getAttribute("entry-point-ref");
		String authenticationManagerRef = element.getAttribute("authentication-manager-ref");
		String tokenExtractorRef = element.getAttribute("token-extractor-ref");
		String entryAuthDetailsSource = element.getAttribute("auth-details-source-ref");
		String stateless = element.getAttribute("stateless");

		// configure the protected resource filter
		BeanDefinitionBuilder protectedResourceFilterBean = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2AuthenticationProcessingFilter.class);

		if (StringUtils.hasText(authenticationManagerRef)) {
			protectedResourceFilterBean.addPropertyReference("authenticationManager", authenticationManagerRef);
		}
		else {

			BeanDefinitionBuilder authenticationManagerBean = BeanDefinitionBuilder
					.rootBeanDefinition(OAuth2AuthenticationManager.class);
			
			authenticationManagerBean.addPropertyReference("tokenServices", tokenServicesRef);

			if (StringUtils.hasText(resourceId)) {
				authenticationManagerBean.addPropertyValue("resourceId", resourceId);
			}

			protectedResourceFilterBean.addPropertyValue("authenticationManager",
					authenticationManagerBean.getBeanDefinition());

		}

		if (StringUtils.hasText(entryPointRef)) {
			protectedResourceFilterBean.addPropertyReference("authenticationEntryPoint", entryPointRef);
		}

		if (StringUtils.hasText(entryAuthDetailsSource)) {
			protectedResourceFilterBean.addPropertyReference("authenticationDetailsSource", entryAuthDetailsSource);
		}

		if (StringUtils.hasText(tokenExtractorRef)) {
			protectedResourceFilterBean.addPropertyReference("tokenExtractor", tokenExtractorRef);
		}

		if (StringUtils.hasText(stateless)) {
			protectedResourceFilterBean.addPropertyValue("stateless", stateless);
		}

		return protectedResourceFilterBean.getBeanDefinition();

	}

}
