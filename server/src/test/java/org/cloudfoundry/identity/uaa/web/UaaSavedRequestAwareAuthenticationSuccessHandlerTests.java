/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.web;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE;
import static org.junit.Assert.assertEquals;


public class UaaSavedRequestAwareAuthenticationSuccessHandlerTests {

    MockHttpServletRequest request;
    UaaSavedRequestAwareAuthenticationSuccessHandler handler;
    @Before
    public void setUp() {
        request = new MockHttpServletRequest();
        handler = new UaaSavedRequestAwareAuthenticationSuccessHandler();
    }

    @Test
    public void allow_url_override() {
        request.setAttribute(URI_OVERRIDE_ATTRIBUTE, "http://test.com");
        assertEquals("http://test.com", handler.determineTargetUrl(request, new MockHttpServletResponse()));
    }

    @Test
    public void form_parameter_is_overridden() {
        request.setParameter(FORM_REDIRECT_PARAMETER, "http://test.com");
        request.setAttribute(URI_OVERRIDE_ATTRIBUTE, "http://override.test.com");
        assertEquals("http://override.test.com", handler.determineTargetUrl(request, new MockHttpServletResponse()));
    }

    @Test
    public void validFormRedirectIsReturned() {
        String redirectUri = request.getScheme() + "://" + request.getServerName() + "/test";

        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        assertEquals(redirectUri, handler.determineTargetUrl(request, new MockHttpServletResponse()));
    }

    @Test
    public void invalidFormRedirectIsNotReturned() {
        String redirectUri = "http://test.com/test";

        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        assertEquals("/", handler.determineTargetUrl(request, new MockHttpServletResponse()));
    }
}
