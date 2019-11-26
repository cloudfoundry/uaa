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


public class DisableSpringUaaSpringSecurityFilterRegistrationBean implements BeanDefinitionRegistryPostProcessor
{
    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        ListableBeanFactory factory = (ListableBeanFactory) registry;
        String[] filterBeanNames = factory.getBeanNamesForType(Filter.class);
        for (String beanName : filterBeanNames) {
            BeanDefinition beanDefinition = registry.getBeanDefinition(beanName);
            String beanClassName = beanDefinition.getBeanClassName();
            if (beanClassName != null && beanClassName.startsWith("org.cloudfoundry")) {
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
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
    }
}