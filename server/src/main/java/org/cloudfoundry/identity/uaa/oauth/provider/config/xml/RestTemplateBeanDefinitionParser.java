package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.client.DefaultOAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.springframework.aop.scope.ScopedProxyUtils;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

public class RestTemplateBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    private static final String RESOURCE = "resource";

    @Override
    protected Class<?> getBeanClass(Element element) {
        return OAuth2RestTemplate.class;
    }

    @Override
    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {

        String accessTokenProviderRef = element.getAttribute("access-token-provider");

        builder.addConstructorArgReference(element.getAttribute(RESOURCE));

        BeanDefinitionBuilder request = BeanDefinitionBuilder.genericBeanDefinition(DefaultAccessTokenRequest.class);
        request.setScope("request");
        request.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        request.addConstructorArgValue("#{request.parameterMap}");
        request.addPropertyValue("currentUri", "#{request.getAttribute('currentUri')}");

        BeanDefinitionHolder requestDefinition = new BeanDefinitionHolder(request.getRawBeanDefinition(), parserContext
                .getReaderContext().generateBeanName(request.getRawBeanDefinition()));
        parserContext.getRegistry().registerBeanDefinition(requestDefinition.getBeanName(),
                requestDefinition.getBeanDefinition());
        BeanDefinitionHolder requestHolder = ScopedProxyUtils.createScopedProxy(requestDefinition,
                parserContext.getRegistry(), false);

        BeanDefinitionBuilder scopedContext = BeanDefinitionBuilder
                .genericBeanDefinition(DefaultOAuth2ClientContext.class);
        scopedContext.setScope("session");
        scopedContext.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        BeanDefinitionHolder contextDefinition = new BeanDefinitionHolder(scopedContext.getRawBeanDefinition(),
                parserContext.getReaderContext().generateBeanName(scopedContext.getRawBeanDefinition()));
        parserContext.getRegistry().registerBeanDefinition(contextDefinition.getBeanName(),
                contextDefinition.getBeanDefinition());
        BeanDefinitionHolder contextHolder = ScopedProxyUtils.createScopedProxy(contextDefinition,
                parserContext.getRegistry(), false);
        scopedContext.addConstructorArgValue(requestHolder.getBeanDefinition());

        BeanDefinitionBuilder bareContext = BeanDefinitionBuilder
                .genericBeanDefinition(DefaultOAuth2ClientContext.class);

        BeanDefinitionBuilder context = BeanDefinitionBuilder
                .genericBeanDefinition(OAuth2ClientContextFactoryBean.class);

        context.addPropertyValue("scopedContext", contextHolder.getBeanDefinition());
        context.addPropertyValue("bareContext", bareContext.getBeanDefinition());
        context.addPropertyReference(RESOURCE, element.getAttribute(RESOURCE));

        builder.addConstructorArgValue(context.getBeanDefinition());
        if (StringUtils.hasText(accessTokenProviderRef)) {
            builder.addPropertyReference("accessTokenProvider", accessTokenProviderRef);
        }

        parserContext.getDelegate().parsePropertyElements(element, builder.getBeanDefinition());

    }

}
