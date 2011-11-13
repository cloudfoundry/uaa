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
package org.cloudfoundry.identity.uaa.error;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.AbstractHandlerExceptionResolver;

/**
 * @author Dave Syer
 */
public class GenericExceptionResolver extends AbstractHandlerExceptionResolver {

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
			new HttpMessageConverter<?>[0]);

	private ResponseGenerator<Exception> responseGenerator = new DefaultExceptionResponseGenerator();

	/**
	 * @param responseGenerator the responseGenerator to set
	 */
	public void setResponseGenerator(ResponseGenerator<Exception> responseGenerator) {
		this.responseGenerator = responseGenerator;
	}

	/**
	 * Set the message body converters to use.
	 * <p>
	 * These converters are used to convert from and to HTTP requests and responses.
	 */
	public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
		this.messageConverters = messageConverters;
	}

	public HttpMessageConverter<?>[] getMessageConverters() {
		return messageConverters;
	}

	@Override
	protected ModelAndView doResolveException(HttpServletRequest request, HttpServletResponse response, Object handler,
			Exception ex) {
		if (!responseGenerator.supports(ex.getClass())) {
			return null;
		}
		ResponseEntity<? extends Exception> responseEntity = responseGenerator.generateResponseEntity(handler, ex);
		if (responseEntity == null) {
			return null;
		}
		try {
			HttpInputMessage inputMessage = createHttpInputMessage(request);
			HttpOutputMessage outputMessage = createHttpOutputMessage(response);
			for (MediaType mediaType : inputMessage.getHeaders().getAccept()) {
				if (MediaType.APPLICATION_JSON.isCompatibleWith(mediaType)) {
					handleHttpEntityResponse(responseEntity, inputMessage, outputMessage);
					return new ModelAndView();
				}
			}
		}
		catch (Exception invocationEx) {
			logger.error("Invoking request method resulted in exception", invocationEx);
		}
		return null;
	}

	/**
	 * Template method for creating a new HttpInputMessage instance.
	 * <p>
	 * The default implementation creates a standard {@link ServletServerHttpRequest}. This can be overridden for custom
	 * {@code HttpInputMessage} implementations
	 * @param servletRequest current HTTP request
	 * @return the HttpInputMessage instance to use
	 * @throws Exception in case of errors
	 */
	protected HttpInputMessage createHttpInputMessage(HttpServletRequest servletRequest) throws Exception {
		return new ServletServerHttpRequest(servletRequest);
	}

	/**
	 * Template method for creating a new HttpOuputMessage instance.
	 * <p>
	 * The default implementation creates a standard {@link ServletServerHttpResponse}. This can be overridden for
	 * custom {@code HttpOutputMessage} implementations
	 * @param servletResponse current HTTP response
	 * @return the HttpInputMessage instance to use
	 * @throws Exception in case of errors
	 */
	protected HttpOutputMessage createHttpOutputMessage(HttpServletResponse servletResponse) throws Exception {
		return new ServletServerHttpResponse(servletResponse);
	}

	private void handleHttpEntityResponse(ResponseEntity<? extends Exception> responseEntity,
			HttpInputMessage inputMessage, HttpOutputMessage outputMessage) throws Exception {
		if (outputMessage instanceof ServerHttpResponse) {
			((ServerHttpResponse) outputMessage).setStatusCode(responseEntity.getStatusCode());
		}
		if (responseEntity.getBody() != null) {
			writeWithMessageConverters(responseEntity.getBody(), inputMessage, outputMessage);
		}
		else {
			// flush headers
			outputMessage.getBody();
		}
	}

	@SuppressWarnings("unchecked")
	private void writeWithMessageConverters(Object returnValue, HttpInputMessage inputMessage,
			HttpOutputMessage outputMessage) throws IOException, HttpMediaTypeNotAcceptableException {
		List<MediaType> acceptedMediaTypes = inputMessage.getHeaders().getAccept();
		if (acceptedMediaTypes.isEmpty()) {
			acceptedMediaTypes = Collections.singletonList(MediaType.ALL);
		}
		MediaType.sortByQualityValue(acceptedMediaTypes);
		Class<?> returnValueType = returnValue.getClass();
		List<MediaType> allSupportedMediaTypes = new ArrayList<MediaType>();
		if (getMessageConverters() != null) {
			for (MediaType acceptedMediaType : acceptedMediaTypes) {
				for (@SuppressWarnings("rawtypes")
				HttpMessageConverter messageConverter : getMessageConverters()) {
					if (messageConverter.canWrite(returnValueType, acceptedMediaType)) {
						messageConverter.write(returnValue, acceptedMediaType, outputMessage);
						if (logger.isDebugEnabled()) {
							MediaType contentType = outputMessage.getHeaders().getContentType();
							if (contentType == null) {
								contentType = acceptedMediaType;
							}
							logger.debug("Written [" + returnValue + "] as \"" + contentType + "\" using ["
									+ messageConverter + "]");
						}
						// this.responseArgumentUsed = true;
						return;
					}
				}
			}
			for (@SuppressWarnings("rawtypes")
			HttpMessageConverter messageConverter : messageConverters) {
				allSupportedMediaTypes.addAll(messageConverter.getSupportedMediaTypes());
			}
		}
		throw new HttpMediaTypeNotAcceptableException(allSupportedMediaTypes);
	}

}
