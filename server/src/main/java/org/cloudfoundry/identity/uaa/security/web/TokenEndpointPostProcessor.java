package org.cloudfoundry.identity.uaa.security.web;

import java.util.HashSet;
import java.util.Set;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;

public class TokenEndpointPostProcessor implements BeanPostProcessor {

  @Override
  public Object postProcessBeforeInitialization(Object bean, String beanName)
      throws BeansException {
    return bean;
  }

  @Override
  public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
    if (bean != null && bean instanceof TokenEndpoint) {
      TokenEndpoint endpoint = (TokenEndpoint) bean;
      Set<HttpMethod> methods = new HashSet<>();
      methods.add(HttpMethod.POST);
      methods.add(HttpMethod.GET);
      endpoint.setAllowedRequestMethods(methods);
    }
    return bean;
  }
}
