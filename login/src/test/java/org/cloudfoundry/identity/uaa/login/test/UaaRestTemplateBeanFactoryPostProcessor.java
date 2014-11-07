package org.cloudfoundry.identity.uaa.login.test;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.web.client.RestTemplate;

public class UaaRestTemplateBeanFactoryPostProcessor implements BeanFactoryPostProcessor {

    /*
     * Replaces the authorizationTemplate with a standard RestTemplate for
     * compatibility with MockRestServiceServer
     */

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory configurableListableBeanFactory) throws BeansException {
        BeanDefinition beanDefinition = configurableListableBeanFactory.getBeanDefinition("authorizationTemplate");
        beanDefinition.setBeanClassName(RestTemplate.class.getCanonicalName());
        beanDefinition.getConstructorArgumentValues().clear();
    }
}
