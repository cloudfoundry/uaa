/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.security.web;


import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.TokenEndpoint;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.http.HttpMethod;

import java.util.HashSet;
import java.util.Set;

public class TokenEndpointPostProcessor implements BeanPostProcessor {

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean != null && bean instanceof TokenEndpoint endpoint) {
            Set<HttpMethod> methods = new HashSet<>();
            methods.add(HttpMethod.POST);
            methods.add(HttpMethod.GET);
            endpoint.setAllowedRequestMethods(methods);
        }
        return bean;
    }
}
