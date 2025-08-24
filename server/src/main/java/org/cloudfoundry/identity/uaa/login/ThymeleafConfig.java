/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.login;

import nz.net.ultraq.thymeleaf.layoutdialect.LayoutDialect;
import org.cloudfoundry.identity.uaa.web.ForwardAwareInternalResourceViewResolver;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.accept.ContentNegotiationManager;
import org.springframework.web.servlet.view.BeanNameViewResolver;
import org.springframework.web.servlet.view.ContentNegotiatingViewResolver;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;
import org.thymeleaf.dialect.IDialect;
import org.thymeleaf.extras.springsecurity6.dialect.SpringSecurityDialect;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ITemplateResolver;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Configuration
public class ThymeleafConfig {

    @Bean
    public ThymeleafViewResolver thymeleafViewResolver(ApplicationContext context) {
        ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
        viewResolver.setTemplateEngine(webTemplateEngine(context));
        return viewResolver;
    }

    @Bean
    public SpringTemplateEngine webTemplateEngine(ApplicationContext context) {
        SpringTemplateEngine springTemplateEngine = new SpringTemplateEngine();

        springTemplateEngine.setTemplateResolver(webTemplateResolver(context));

        Set<IDialect> additionalDialects = new HashSet<>();
        additionalDialects.add(new LayoutDialect());
        additionalDialects.add(new SpringSecurityDialect());
        springTemplateEngine.setAdditionalDialects(additionalDialects);

        return springTemplateEngine;
    }

    @Bean
    public ITemplateResolver webTemplateResolver(ApplicationContext context) {
        SpringResourceTemplateResolver templateResolver = baseHtmlTemplateResolver(context);
        templateResolver.setPrefix("classpath:/templates/web/");
        return templateResolver;
    }

    @Bean
    public SpringTemplateEngine mailTemplateEngine(ApplicationContext context) {
        SpringTemplateEngine springTemplateEngine = new SpringTemplateEngine();
        springTemplateEngine.setTemplateResolver(mailTemplateResolver(context));
        return springTemplateEngine;
    }

    @Bean
    public ITemplateResolver mailTemplateResolver(ApplicationContext context) {
        SpringResourceTemplateResolver templateResolver = baseHtmlTemplateResolver(context);
        templateResolver.setPrefix("classpath:/templates/mail/");
        return templateResolver;
    }

    @Bean
    public org.springframework.web.servlet.view.ContentNegotiatingViewResolver viewResolver(ApplicationContext context,
            ContentNegotiationManager contentNegotiationManager) {
        ContentNegotiatingViewResolver resolver = new ContentNegotiatingViewResolver();
        ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();

        viewResolver.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        viewResolver.setTemplateEngine(webTemplateEngine(context));
        ForwardAwareInternalResourceViewResolver forwardAwareInternalResourceViewResolver = new ForwardAwareInternalResourceViewResolver();
        BeanNameViewResolver beanNameViewResolver = new BeanNameViewResolver();
        resolver.setViewResolvers(Arrays.asList(viewResolver, forwardAwareInternalResourceViewResolver, beanNameViewResolver));

        MappingJackson2JsonView jackson2JsonView = new MappingJackson2JsonView();
        jackson2JsonView.setExtractValueFromSingleKeyModel(true);
        resolver.setDefaultViews(Collections.singletonList(jackson2JsonView));

        resolver.setContentNegotiationManager(contentNegotiationManager);
        return resolver;
    }

    private SpringResourceTemplateResolver baseHtmlTemplateResolver(ApplicationContext context) {
        SpringResourceTemplateResolver templateResolver = new SpringResourceTemplateResolver();
        templateResolver.setSuffix(".html");
        templateResolver.setTemplateMode(TemplateMode.HTML);
        templateResolver.setApplicationContext(context);
        return templateResolver;
    }

}
