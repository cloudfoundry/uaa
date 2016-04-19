/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login.test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.thymeleaf.dialect.IDialect;
import org.thymeleaf.extras.springsecurity3.dialect.SpringSecurityDialect;
import org.thymeleaf.spring4.SpringTemplateEngine;
import org.thymeleaf.spring4.resourceresolver.SpringResourceResourceResolver;
import org.thymeleaf.spring4.view.ThymeleafViewResolver;
import org.thymeleaf.templateresolver.TemplateResolver;

import java.util.HashSet;
import java.util.Set;
import nz.net.ultraq.thymeleaf.LayoutDialect;

@Configuration
public class ThymeleafConfig {

    @Bean
    public ThymeleafViewResolver thymeleafViewResolver() {
        ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
        viewResolver.setTemplateEngine(webTemplateEngine());
        return viewResolver;
    }

    @Bean
    public SpringTemplateEngine webTemplateEngine() {
        SpringTemplateEngine springTemplateEngine = new SpringTemplateEngine();

        springTemplateEngine.setTemplateResolver(webTemplateResolver());

        Set<IDialect> additionalDialects = new HashSet<IDialect>();
        additionalDialects.add(new LayoutDialect());
        additionalDialects.add(new SpringSecurityDialect());
        springTemplateEngine.setAdditionalDialects(additionalDialects);

        return springTemplateEngine;
    }

    @Bean
    public TemplateResolver webTemplateResolver() {
        TemplateResolver templateResolver = baseHtmlTemplateResolver();
        templateResolver.setPrefix("classpath:/templates/web/");
        return templateResolver;
    }

    @Bean
    public SpringTemplateEngine mailTemplateEngine() {
        SpringTemplateEngine springTemplateEngine = new SpringTemplateEngine();
        springTemplateEngine.setTemplateResolver(mailTemplateResolver());
        return springTemplateEngine;
    }

    @Bean
    public TemplateResolver mailTemplateResolver() {
        TemplateResolver templateResolver = baseHtmlTemplateResolver();
        templateResolver.setPrefix("classpath:/templates/mail/");
        return templateResolver;
    }

    private TemplateResolver baseHtmlTemplateResolver() {
        TemplateResolver templateResolver = new TemplateResolver();
        templateResolver.setResourceResolver(springResourceResourceResolver());
        templateResolver.setSuffix(".html");
        templateResolver.setTemplateMode("HTML5");
        return templateResolver;
    }

    @Bean
    public SpringResourceResourceResolver springResourceResourceResolver() {
        return new SpringResourceResourceResolver();
    }
}
