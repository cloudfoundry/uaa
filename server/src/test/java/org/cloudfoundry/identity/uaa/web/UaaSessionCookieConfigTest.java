/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.web;

import javax.servlet.ServletContext;
import javax.servlet.SessionCookieConfig;
import javax.servlet.SessionTrackingMode;
import java.util.Set;

import org.junit.Test;
import org.mockito.ArgumentCaptor;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UaaSessionCookieConfigTest {

    @Test
    public void testSetServletContext() throws Exception {
        ServletContext context = mock(ServletContext.class);
        UaaSessionCookieConfig config = new UaaSessionCookieConfig();
        SessionCookieConfig cookie = mock(SessionCookieConfig.class);
        when(context.getSessionCookieConfig()).thenReturn(cookie);
        doThrow(new IllegalStateException()).when(cookie).setHttpOnly(anyBoolean());
        config.setServletContext(context);
        verify(cookie, never()).setSecure(anyBoolean());
    }

    @Test
    public void verify_cookie_tracking_mode() throws Exception {
        ServletContext context = mock(ServletContext.class);
        UaaSessionCookieConfig config = new UaaSessionCookieConfig();
        SessionCookieConfig cookie = mock(SessionCookieConfig.class);
        when(context.getSessionCookieConfig()).thenReturn(cookie);
        config.setServletContext(context);
        ArgumentCaptor<Set<SessionTrackingMode>> tracking = ArgumentCaptor.forClass(Set.class);
        verify(context).setSessionTrackingModes(tracking.capture());
        assertThat(tracking.getValue(), containsInAnyOrder(SessionTrackingMode.COOKIE));
    }
}