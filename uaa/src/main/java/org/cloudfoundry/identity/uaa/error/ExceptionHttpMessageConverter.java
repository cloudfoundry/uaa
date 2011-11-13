/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cloudfoundry.identity.uaa.error;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.web.client.RestTemplate;

/**
 * @author Dave Syer
 * 
 */
public class ExceptionHttpMessageConverter extends AbstractHttpMessageConverter<Exception> {

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
			new HttpMessageConverter<?>[0]);

	/**
	 * Set the message body converters to use.
	 * <p>
	 * These converters are used to convert from and to HTTP requests and responses.
	 */
	public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
		this.messageConverters = messageConverters;
	}
	
	@Override
	public List<MediaType> getSupportedMediaTypes() {
		Set<MediaType> list = new LinkedHashSet<MediaType>();
		for (HttpMessageConverter<?> converter : messageConverters) {
			list.addAll(converter.getSupportedMediaTypes());
		}
		return new ArrayList<MediaType>(list);
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return Exception.class.isAssignableFrom(clazz);
	}

	@Override
	protected Exception readInternal(Class<? extends Exception> clazz, HttpInputMessage inputMessage)
			throws IOException, HttpMessageNotReadableException {
		for (HttpMessageConverter<?> converter : messageConverters) {
			for (MediaType mediaType : converter.getSupportedMediaTypes()) {
				if (converter.canRead(Map.class, mediaType)) {
					@SuppressWarnings({ "rawtypes", "unchecked" })
					HttpMessageConverter<Map> messageConverter = (HttpMessageConverter<Map>) converter;
					@SuppressWarnings("unchecked")
					Map<String, String> map = messageConverter.read(Map.class, inputMessage);
					return getException(map);
				}
			}
		}
		return null;
	}

	private Exception getException(Map<String, String> map) {
		return new RuntimeException(map.get("message"));
	}

	@Override
	protected void writeInternal(Exception e, HttpOutputMessage outputMessage) throws IOException,
			HttpMessageNotWritableException {
		Map<String, String> map = new HashMap<String, String>();
		map.put("error", e.getClass().getName());
		map.put("message", e.getMessage());
		StringWriter trace = new StringWriter();
		e.printStackTrace(new PrintWriter(trace));
		map.put("trace", trace.toString());
		for (HttpMessageConverter<?> converter : messageConverters) {
			for (MediaType mediaType : converter.getSupportedMediaTypes()) {
				if (converter.canWrite(Map.class, mediaType)) {
					@SuppressWarnings({ "rawtypes", "unchecked" })
					HttpMessageConverter<Map> messageConverter = (HttpMessageConverter<Map>) converter;
					messageConverter.write(map, mediaType, outputMessage);
					return;
				}
			}
		}
	}

}
