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

import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Dave Syer
 *
 */
public class ExceptionReportHttpMessageConverter extends AbstractHttpMessageConverter<ExceptionReport> {

    private static final HttpMessageConverter<?>[] DEFAULT_MESSAGE_CONVERTERS = new RestTemplate()
            .getMessageConverters().toArray(
            new HttpMessageConverter<?>[0]);

    private HttpMessageConverter<?>[] messageConverters = DEFAULT_MESSAGE_CONVERTERS;

    /**
     * Set the message body converters to use.
     * <p>
     * These converters are used to convert from and to HTTP requests and
     * responses.
     */
    public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
        this.messageConverters = messageConverters;
    }

    @Override
    public List<MediaType> getSupportedMediaTypes() {
        Set<MediaType> list = new LinkedHashSet<>();
        for (HttpMessageConverter<?> converter : messageConverters) {
            list.addAll(converter.getSupportedMediaTypes());
        }
        return new ArrayList<>(list);
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return ExceptionReport.class.isAssignableFrom(clazz);
    }

    @Override
    protected ExceptionReport readInternal(Class<? extends ExceptionReport> clazz, HttpInputMessage inputMessage)
            throws IOException, HttpMessageNotReadableException {
        for (HttpMessageConverter<?> converter : messageConverters) {
            for (MediaType mediaType : converter.getSupportedMediaTypes()) {
                if (converter.canRead(Map.class, mediaType)) {
                    @SuppressWarnings({"rawtypes", "unchecked"})
                    HttpMessageConverter<Map> messageConverter = (HttpMessageConverter<Map>) converter;
                    @SuppressWarnings("unchecked")
                    Map<String, String> map = messageConverter.read(Map.class, inputMessage);
                    return new ExceptionReport(getException(map));
                }
            }
        }
        return null;
    }

    private Exception getException(Map<String, String> map) {
        return new RuntimeException(map.get("message"));
    }

    @Override
    protected void writeInternal(ExceptionReport report, HttpOutputMessage outputMessage) throws IOException,
            HttpMessageNotWritableException {
        Exception e = report.getException();
        Map<String, Object> map = new HashMap<>();
        map.put("error", UaaStringUtils.getErrorName(e));
        map.put("message", e.getMessage());
        map.put("error_description", e.getMessage());
        if (report.getExtraInfo() != null) {
            map.putAll(report.getExtraInfo());
        }
        if (report.isTrace()) {
            StringWriter trace = new StringWriter();
            e.printStackTrace(new PrintWriter(trace));
            map.put("trace", trace.toString());
        }
        for (HttpMessageConverter<?> converter : messageConverters) {
            for (MediaType mediaType : converter.getSupportedMediaTypes()) {
                if (converter.canWrite(Map.class, mediaType)) {
                    @SuppressWarnings({"rawtypes", "unchecked"})
                    HttpMessageConverter<Map> messageConverter = (HttpMessageConverter<Map>) converter;
                    messageConverter.write(map, mediaType, outputMessage);
                    return;
                }
            }
        }
    }

}
