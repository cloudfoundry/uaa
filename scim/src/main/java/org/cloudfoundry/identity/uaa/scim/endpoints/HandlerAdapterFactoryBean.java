/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.scim.endpoints;

import java.util.Arrays;

import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.method.support.HandlerMethodReturnValueHandler;
import org.springframework.web.servlet.HandlerAdapter;
import org.springframework.web.servlet.mvc.annotation.AnnotationMethodHandlerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

/**
 * Factory for a handler adapter that sniffs the results from {@link RequestMapping} method executions and adds an ETag
 * header if the result is a {@link ScimCore}. Inject into application context as anonymous bean.
 * 
 * @author Dave Syer
 * 
 */
public class HandlerAdapterFactoryBean implements FactoryBean<HandlerAdapter>, ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Override
	public HandlerAdapter getObject() throws Exception {
		RequestMappingHandlerAdapter adapter = new RequestMappingHandlerAdapter();
		adapter.setApplicationContext(applicationContext);
        adapter.setMessageConverters(new RestTemplate().getMessageConverters());
		adapter.setOrder(0);
        adapter.setReturnValueHandlers(Arrays
				.<HandlerMethodReturnValueHandler> asList(new ScimEtagHandlerMethodReturnValueHandler(new RestTemplate().getMessageConverters())));
		adapter.afterPropertiesSet();
		return adapter;
	}

    @Override
	public Class<?> getObjectType() {
		return AnnotationMethodHandlerAdapter.class;
	}

	@Override
	public boolean isSingleton() {
		return true;
	}

    @Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}
}
