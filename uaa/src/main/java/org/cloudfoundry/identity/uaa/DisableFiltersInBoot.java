package org.cloudfoundry.identity.uaa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.springframework.lang.NonNull;

import javax.servlet.Filter;

/**
 * Spring Security filters are created as beans in the XML files and then aggregated into
 * FilterChainProxy which is registered with Spring Boot. However, Spring Boot registers
 * all Beans that implement Filter with the servlet container. This means that all the
 * Security Filters are executed twice. Additionally, the Filter is going to be executed
 * for every URL since Boot's default is to register for every URL.
 *
 * This is a post processor that marks all UAA Filter's as disabled (i.e. do not register
 * it with the servlet container). This way it is only executed within FilterChainProxy.
 *
 * @author Rob Winch
 */
public class DisableFiltersInBoot implements BeanDefinitionRegistryPostProcessor {

    private static final Logger logger = LoggerFactory.getLogger(DisableFiltersInBoot.class);

    @Override
    public void postProcessBeanDefinitionRegistry(
            final @NonNull BeanDefinitionRegistry registry
    ) throws BeansException {
        ListableBeanFactory factory = (ListableBeanFactory) registry;
        String[] filterBeanNames = factory.getBeanNamesForType(Filter.class);
        for (String beanName : filterBeanNames) {
            BeanDefinition beanDefinition = registry.getBeanDefinition(beanName);
            String beanClassName = beanDefinition.getBeanClassName();
            if (beanClassName != null) {
                logger.warn("Adding disabled filter registration for {}, {}", beanName, beanClassName);
                BeanDefinitionBuilder filterRegistrationBldr = BeanDefinitionBuilder.rootBeanDefinition(FilterRegistrationBean.class);
                filterRegistrationBldr.addPropertyReference("filter", beanName);
                filterRegistrationBldr.addPropertyValue("enabled", false);

                AbstractBeanDefinition filterRegistrationBeanDefinition = filterRegistrationBldr.getBeanDefinition();
                String filterRegistrationBeanName = BeanDefinitionReaderUtils.generateBeanName(beanDefinition, registry);
                registry.registerBeanDefinition(filterRegistrationBeanName, filterRegistrationBeanDefinition);
            } else {
                logger.warn("Not adding filter registration for {}, {}", beanName, beanClassName);
            }
        }
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory)
            throws BeansException {
    }
}
