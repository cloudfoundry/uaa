/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.web;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.servlet.View;

/**
 * @author Dave Syer
 * 
 */
public class ConvertingExceptionView implements View {

    private static final Logger logger = LoggerFactory.getLogger(ConvertingExceptionView.class);

    private final ResponseEntity<? extends ExceptionReport> responseEntity;

    private final HttpMessageConverter<?>[] messageConverters;

    public ConvertingExceptionView(ResponseEntity<? extends ExceptionReport> responseEntity,
            HttpMessageConverter<?>[] messageConverters) {
        this.responseEntity = responseEntity;
        this.messageConverters = messageConverters;
    }

    @Override
    public String getContentType() {
        return MediaType.APPLICATION_JSON_VALUE;
    }

    @Override
    public void render(Map<String, ?> model, HttpServletRequest request, HttpServletResponse response) {
        try {
            HttpOutputMessage outputMessage = createHttpOutputMessage(response);
            handleHttpEntityResponse(responseEntity, outputMessage);
        } catch (Exception invocationEx) {
            logger.error("Invoking request method resulted in exception", invocationEx);
        }
    }

    /**
     * Template method for creating a new HttpOuputMessage instance.
     * <p>
     * The default implementation creates a standard
     * {@link ServletServerHttpResponse}. This can be overridden for custom
     * {@code HttpOutputMessage} implementations
     * 
     * @param servletResponse current HTTP response
     * @return the HttpInputMessage instance to use
     */
    protected HttpOutputMessage createHttpOutputMessage(HttpServletResponse servletResponse) {
        return new ServletServerHttpResponse(servletResponse);
    }

    private void handleHttpEntityResponse(ResponseEntity<? extends ExceptionReport> responseEntity,
            HttpOutputMessage outputMessage) throws Exception {
        if (outputMessage instanceof ServerHttpResponse response) {
            response.setStatusCode(responseEntity.getStatusCode());
        }
        if (responseEntity.getBody() != null) {
            writeWithMessageConverters(responseEntity.getBody(), outputMessage);
        } else {
            // flush headers
            outputMessage.getBody();
        }
    }

    @SuppressWarnings("unchecked")
    private void writeWithMessageConverters(Object returnValue,
            HttpOutputMessage outputMessage) throws IOException, HttpMediaTypeNotAcceptableException {
        Class<?> returnValueType = returnValue.getClass();
        if (messageConverters != null) {
            for (@SuppressWarnings("rawtypes")
            HttpMessageConverter messageConverter : messageConverters) {
                if (messageConverter.canWrite(returnValueType, MediaType.APPLICATION_JSON)) {
                    messageConverter.write(returnValue, MediaType.APPLICATION_JSON, outputMessage);
                    if (logger.isDebugEnabled()) {
                        MediaType contentType = outputMessage.getHeaders().getContentType();
                        if (contentType == null) {
                            contentType = MediaType.APPLICATION_JSON;
                        }
                        logger.debug("Written [{}] as \"{}\" using [{}]", returnValue, contentType, messageConverter);
                    }
                    return;
                }
            }
        }
        throw new HttpMediaTypeNotAcceptableException(List.of(MediaType.APPLICATION_JSON));
    }

}
