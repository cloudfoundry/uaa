/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.util.NullifyFields;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

public class TestClassNullifier {

    private static volatile Class<?> clazz;

    @BeforeEach
    void trackClass() {
        clazz = this.getClass();
    }

    @AfterEach
    void nullifyInstanceFields() throws Exception {
        NullifyFields.nullifyFields(this.getClass(), this, false);
    }

    @AfterAll
    static void nullifyClassFields() throws Exception {
        NullifyFields.nullifyFields(clazz, null, true);
        clazz = null;
        System.gc();
    }

    public static InternalResourceViewResolver getResolver() {
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/jsp");
        viewResolver.setSuffix(".jsp");
        return viewResolver;
    }
}
