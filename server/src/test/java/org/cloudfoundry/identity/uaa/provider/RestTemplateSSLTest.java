/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.cache.ExpiringUrlCache;
import org.cloudfoundry.identity.uaa.util.RestTemplateFactory;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.junit.Test;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

import static org.junit.Assert.assertNotNull;

public class RestTemplateSSLTest {

    @Test
    public void test() throws Exception {
        RestTemplate template = new RestTemplateFactory().getRestTemplate(true);
        template.setErrorHandler(new ResponseErrorHandler() {
            @Override public boolean hasError(ClientHttpResponse response) throws IOException { return false; }
            @Override public void handleError(ClientHttpResponse response) throws IOException {}
        });
        ExpiringUrlCache cache = new ExpiringUrlCache(1, new TimeServiceImpl(), 1);
        byte[] data = cache.getUrlContent("https://idp.login.uaa-acceptance.cf-app.com:443/saml/idp/metadata", template);
        assertNotNull(data);
        System.out.println(new String(data));
    }
}
