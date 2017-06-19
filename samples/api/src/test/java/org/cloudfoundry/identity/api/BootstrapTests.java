/*******************************************************************************
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
package org.cloudfoundry.identity.api;

import org.junit.Test;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.support.XmlWebApplicationContext;

import javax.servlet.RequestDispatcher;

public class BootstrapTests {

    @Test
    public void testRootContext() throws Exception {
        MockServletContext servletContext = new MockServletContext() {
            @Override
            public RequestDispatcher getNamedDispatcher(String path) {
                return new MockRequestDispatcher("/");
            }

            @Override
            public String getVirtualServerName() {
                return "localhost";
            }
        };
        XmlWebApplicationContext context = new XmlWebApplicationContext();
        context.setConfigLocation("file:src/main/webapp/WEB-INF/spring-servlet.xml");
        context.setServletContext(servletContext);
        context.refresh();
        context.close();
    }

}
