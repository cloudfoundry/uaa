/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.config;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.MethodParameter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodReturnValueHandler;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.HandlerAdapter;
import org.springframework.web.servlet.mvc.annotation.AnnotationMethodHandlerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.RequestResponseBodyMethodProcessor;

/**
 * Factory for a handler adapter that sniffs the results from {@link RequestMapping} method executions and adds an ETag
 * header if the result is a {@link ScimUser}. Inject into application context as anonymous bean.
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
		adapter.setMessageConverters(getMessageConverters());
		adapter.setOrder(0);
		adapter.setReturnValueHandlers(Arrays
				.<HandlerMethodReturnValueHandler> asList(new ScimEtagHandlerMethodReturnValueHandler(getMessageConverters())));
		adapter.afterPropertiesSet();
		return adapter;
	}

	private List<HttpMessageConverter<?>> getMessageConverters() {
		return new RestTemplate().getMessageConverters();
	}

	@Override
	public Class<?> getObjectType() {
		return AnnotationMethodHandlerAdapter.class;
	}

	@Override
	public boolean isSingleton() {
		return true;
	}

	private static class ScimEtagHandlerMethodReturnValueHandler extends RequestResponseBodyMethodProcessor {

		public ScimEtagHandlerMethodReturnValueHandler(List<HttpMessageConverter<?>> messageConverters) {
			super(messageConverters);
		}

		@Override
		public boolean supportsReturnType(MethodParameter returnType) {
			return ScimUser.class.isAssignableFrom(returnType.getMethod().getReturnType());
		}

		@Override
		public void handleReturnValue(Object returnValue, MethodParameter returnType,
				ModelAndViewContainer mavContainer, NativeWebRequest webRequest) throws IOException,
				HttpMediaTypeNotAcceptableException {
			if (returnValue instanceof ScimUser) {
				HttpServletResponse response = webRequest.getNativeResponse(HttpServletResponse.class);
				response.addHeader("ETag", "\"" + ((ScimUser) returnValue).getVersion() + "\"");
			}
			super.handleReturnValue(returnValue, returnType, mavContainer, webRequest);
		}

	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}
}
