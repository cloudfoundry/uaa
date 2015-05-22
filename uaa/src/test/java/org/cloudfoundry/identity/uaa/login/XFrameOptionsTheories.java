/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER;
import static org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

public class XFrameOptionsTheories extends InjectedMockContextTest {

    @Test
    public void responsesHaveXFrameOptionsHeaderHtml() throws Exception {
        RequestBuilder request = MockMvcRequestBuilders.get("/login").accept(MediaType.TEXT_HTML);
        getMockMvc().perform(request).andExpect(header().string(XFRAME_OPTIONS_HEADER, DENY.toString()));
    }

    @Test
    public void responsesHaveXFrameOptionsHeaderJson() throws Exception {
        RequestBuilder request = MockMvcRequestBuilders.get("/login").accept(MediaType.APPLICATION_JSON);
        getMockMvc().perform(request).andExpect(header().string(XFRAME_OPTIONS_HEADER, DENY.toString()));
    }

}
