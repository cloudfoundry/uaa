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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class NullifyFieldsTest {
    private A a;
    private B b;

    @BeforeEach
    void setUp() {
        // reset static fields
        a = new A();
        a.a1 = new Object();
        a.a2 = new Object();

        b = new B();
        b.b1 = new Object();
        b.b2 = new Object();
    }

    @Test
    void nullifyAllA() throws Exception {
        NullifyFields.nullifyFields(A.class, a, true);
        assertThat(a.a1).isNull();
        assertThat(a.a2).isNull();
        assertThat(a.a3).isNull();
        assertThat(a.a4).isNull();
        assertThat(a.a5).isNull();
        assertThat(A.a0).isNotNull();
        assertThat(a.a6).isNotNull();
    }

    @Test
    void nullifyAllAInstanceFields() throws Exception {
        NullifyFields.nullifyFields(A.class, a, false);
        assertThat(a.a1).isNotNull();
        assertThat(a.a2).isNotNull();
        assertThat(a.a3).isNull();
        assertThat(a.a4).isNull();
        assertThat(a.a5).isNull();
        assertThat(A.a0).isNotNull();
        assertThat(a.a6).isNotNull();
    }

    @Test
    void nullifyAllAClassFields() throws Exception {
        NullifyFields.nullifyFields(A.class, null, true);
        assertThat(a.a1).isNull();
        assertThat(a.a2).isNull();
        assertThat(a.a3).isNotNull();
        assertThat(a.a4).isNotNull();
        assertThat(a.a5).isNotNull();
        assertThat(A.a0).isNotNull();
        assertThat(a.a6).isNotNull();
    }

    @Test
    void nullifyAllB() throws Exception {
        NullifyFields.nullifyFields(B.class, b, true);
        assertThat(b.b1).isNull();
        assertThat(b.b2).isNull();
        assertThat(b.b3).isNull();
        assertThat(b.b4).isNull();
        assertThat(b.b5).isNull();
        assertThat(b.a1).isNull();
        assertThat(((A) b).a2).isNull();
        assertThat(b.a3).isNull();
        assertThat(b.a4).isNull();
        assertThat(((A) b).a5).isNull();
        assertThat(A.a0).isNotNull();
        assertThat(B.b0).isNotNull();
        assertThat(((A) b).a6).isNotNull();
        assertThat(b.b6).isNotNull();
    }

    @Test
    void nullifyAllBInstance() throws Exception {
        NullifyFields.nullifyFields(B.class, b, false);
        assertThat(b.b1).isNotNull();
        assertThat(b.b2).isNotNull();
        assertThat(b.b3).isNull();
        assertThat(b.b4).isNull();
        assertThat(b.b5).isNull();
        assertThat(b.a1).isNotNull();
        assertThat(((A) b).a2).isNotNull();
        assertThat(b.a3).isNull();
        assertThat(b.a4).isNull();
        assertThat(((A) b).a5).isNull();
        assertThat(A.a0).isNotNull();
        assertThat(B.b0).isNotNull();
        assertThat(((A) b).a6).isNotNull();
        assertThat(b.b6).isNotNull();
    }

    @Test
    void nullifyAllBClassFields() throws Exception {
        NullifyFields.nullifyFields(B.class, null, true);
        assertThat(a.a1).isNull();
        assertThat(a.a2).isNull();
        assertThat(a.a3).isNotNull();
        assertThat(a.a4).isNotNull();
        assertThat(a.a5).isNotNull();
        assertThat(b.b1).isNull();
        assertThat(b.b2).isNull();
        assertThat(b.b3).isNotNull();
        assertThat(b.b4).isNotNull();
        assertThat(b.b5).isNotNull();
        assertThat(A.a0).isNotNull();
        assertThat(B.b0).isNotNull();
        assertThat(((A) b).a6).isNotNull();
        assertThat(b.b6).isNotNull();
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

    public static class B extends A {
        public static final Object b0 = new Object();
        public static Object b1 = new Object();
        private static Object b2 = new Object();
        public Object b3 = new Object();
        protected Object b4 = new Object();
        private Object b5 = new Object();
        private final Object b6 = new Object();
    }
}