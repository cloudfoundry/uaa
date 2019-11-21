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
package org.cloudfoundry.identity.uaa;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionReaderUtils;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import javax.servlet.Filter;

/**
 * Spring Security filters are created as beans in the XML files and then aggregated into
 * FilterChainProxy which is registered with Spring Boot. However, Spring Boot registers
 * all Beans that implement Filter with the servlet container. This means that all the
 * Security Fiters are executed twice. Additionally, the Filter is going to be executed
 * for every URL since Boot's default is to register for every URL.
 *
 * This is a post processor that marks all UAA Filter's as disabled (i.e. do not register
 * it with the servlet container). This way it is only executed within FilterChainProxy.
 *
 * @author Rob Winch
 */
public class DisableSpringUaaSpringSecurityFilterRegistrationBean implements BeanDefinitionRegistryPostProcessor {
	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry)
			throws BeansException {
		ListableBeanFactory factory = (ListableBeanFactory) registry;
		String[] filterBeanNames = factory.getBeanNamesForType(Filter.class);
		for(String beanName : filterBeanNames) {
			BeanDefinition beanDefinition = registry.getBeanDefinition(beanName);
			String beanClassName = beanDefinition.getBeanClassName();
			if (beanClassName !=null && beanClassName.startsWith("org.cloudfoundry")) {
				BeanDefinitionBuilder filterRegistrationBldr = BeanDefinitionBuilder.rootBeanDefinition(FilterRegistrationBean.class);
				filterRegistrationBldr.addPropertyReference("filter", beanName);
				filterRegistrationBldr.addPropertyValue("enabled", false);

				AbstractBeanDefinition filterRegistrationBeanDefinition = filterRegistrationBldr.getBeanDefinition();
				String filterRegistrationBeanName = BeanDefinitionReaderUtils.generateBeanName(beanDefinition, registry);
				registry.registerBeanDefinition(filterRegistrationBeanName, filterRegistrationBeanDefinition);
			}
		}
	}

	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory)
			throws BeansException {
	}
}
