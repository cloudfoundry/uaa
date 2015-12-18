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

package org.cloudfoundry.identity.uaa.util;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class NullifyFieldsTest {


    private A a;
    private B b;

    @Before
    public void setUp() {
        a = new A();
        b = new B();
    }

    @Test
    public void testNullifyAllA() throws Exception {
        NullifyFields.nullifyFields(A.class, a, true);
        assertNull(a.a1);
        assertNull(a.a2);
        assertNull(a.a3);
        assertNull(a.a4);
        assertNull(a.a5);
        assertNotNull(A.a0);
        assertNotNull(a.a6);
    }

    @Test
    public void testNullifyAllAInstanceFields() throws Exception {
        NullifyFields.nullifyFields(A.class, a, false);
        assertNotNull(a.a1);
        assertNotNull(a.a2);
        assertNull(a.a3);
        assertNull(a.a4);
        assertNull(a.a5);
        assertNotNull(A.a0);
        assertNotNull(a.a6);
    }

    @Test
    public void testNullifyAllAClassFields() throws Exception {
        NullifyFields.nullifyFields(A.class, null, true);
        assertNull(a.a1);
        assertNull(a.a2);
        assertNotNull(a.a3);
        assertNotNull(a.a4);
        assertNotNull(a.a5);
        assertNotNull(A.a0);
        assertNotNull(a.a6);
    }

    @Test
    public void testNullifyAllB() throws Exception {
        NullifyFields.nullifyFields(B.class, b, true);
        assertNull(b.b1);
        assertNull(b.b2);
        assertNull(b.b3);
        assertNull(b.b4);
        assertNull(b.b5);
        assertNull(b.a1);
        assertNull(((A)b).a2);
        assertNull(b.a3);
        assertNull(b.a4);
        assertNull(((A)b).a5);
        assertNotNull(A.a0);
        assertNotNull(B.b0);
        assertNotNull(((A)b).a6);
        assertNotNull(b.b6);
    }

    @Test
    public void testNullifyAllBInstance() throws Exception {
        NullifyFields.nullifyFields(B.class, b, false);
        assertNotNull(b.b1);
        assertNotNull(b.b2);
        assertNull(b.b3);
        assertNull(b.b4);
        assertNull(b.b5);
        assertNotNull(b.a1);
        assertNotNull(((A) b).a2);
        assertNull(b.a3);
        assertNull(b.a4);
        assertNull(((A)b).a5);
        assertNotNull(A.a0);
        assertNotNull(B.b0);
        assertNotNull(((A)b).a6);
        assertNotNull(b.b6);
    }

    @Test
    public void testNullifyAllBClassFields() throws Exception {
        NullifyFields.nullifyFields(B.class, null, true);
        assertNull(a.a1);
        assertNull(a.a2);
        assertNotNull(a.a3);
        assertNotNull(a.a4);
        assertNotNull(a.a5);
        assertNull(b.b1);
        assertNull(b.b2);
        assertNotNull(b.b3);
        assertNotNull(b.b4);
        assertNotNull(b.b5);
        assertNotNull(A.a0);
        assertNotNull(B.b0);
        assertNotNull(((A)b).a6);
        assertNotNull(b.b6);
    }


    public static class A {
        public static final Object a0 = new Object();
        public static Object a1 = new Object();
        private static Object a2 = new Object();
        public Object a3 = new Object();
        protected Object a4 = new Object();
        private Object a5 = new Object();
        private final Object a6 = new Object();

    }

    public static class B extends  A {
        public static final Object b0 = new Object();
        public static Object b1 = new Object();
        private static Object b2 = new Object();
        public Object b3 = new Object();
        protected Object b4 = new Object();
        private Object b5 = new Object();
        private final Object b6 = new Object();

    }
 }