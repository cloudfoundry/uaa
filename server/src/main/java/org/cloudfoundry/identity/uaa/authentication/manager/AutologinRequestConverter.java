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
package org.cloudfoundry.identity.uaa.authentication.manager;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.login.AutologinRequest;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.LinkedMaskingMultiValueMap;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.util.MultiValueMap;

public class AutologinRequestConverter extends AbstractHttpMessageConverter<AutologinRequest> {
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";

    private final FormHttpMessageConverter formConverter = new FormHttpMessageConverter();
    private final StringHttpMessageConverter stringConverter = new StringHttpMessageConverter();

    public AutologinRequestConverter() {
        setSupportedMediaTypes(Arrays.asList(
                MediaType.APPLICATION_FORM_URLENCODED,
                MediaType.APPLICATION_JSON)
        );
    }

    @Override
    @SuppressWarnings("NullableProblems")
    protected boolean supports(Class<?> clazz) {
        return AutologinRequest.class.isAssignableFrom(clazz);
    }

    public boolean isJsonContent(List<String> contentType) {
        if (contentType != null) {
            for (String s : contentType) {
                if (s != null && s.contains(MediaType.APPLICATION_JSON_VALUE)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    @SuppressWarnings({"NullableProblems", "Convert2Diamond"})
    protected AutologinRequest readInternal(Class<? extends AutologinRequest> clazz, HttpInputMessage inputMessage)
            throws IOException, HttpMessageNotReadableException {

        AutologinRequest result = new AutologinRequest();

        UnaryOperator<String> getValue;
        if (isJsonContent(inputMessage.getHeaders().get(HttpHeaders.CONTENT_TYPE))) {
            Map<String, String> map = JsonUtils.readValue(stringConverter.read(String.class, inputMessage),
                    new TypeReference<Map<String, String>>() {
                    });
            if (map == null) {
                return result;
            }
            getValue = map::get;
        } else {
            MultiValueMap<String, String> map = formConverter.read(null, inputMessage);
            getValue = map::getFirst;
        }
        result.setUsername(getValue.apply(USERNAME));
        result.setPassword(getValue.apply(PASSWORD));
        return result;
    }

    @Override
    @SuppressWarnings("NullableProblems")
    protected void writeInternal(AutologinRequest t, HttpOutputMessage outputMessage) throws IOException,
            HttpMessageNotWritableException {
        MultiValueMap<String, String> map = new LinkedMaskingMultiValueMap<>(PASSWORD);
        if (t.getUsername() != null) {
            map.set(USERNAME, t.getUsername());
        }
        if (t.getPassword() != null) {
            map.set(PASSWORD, t.getPassword());
        }
        formConverter.write(map, MediaType.APPLICATION_FORM_URLENCODED, outputMessage);
    }
}