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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

public class NullifyFields {

    public static void nullifyFields(Class clazz, Object o, boolean staticFieldsToo) throws Exception {
        if (clazz == null) {
            return;
        }
        if (!clazz.getName().startsWith("org.cloudfoundry.identity")) {
            return;
        }
        for (Field f : clazz.getDeclaredFields()) {
            boolean isStatic = Modifier.isStatic(f.getModifiers());
            f.setAccessible(true);
            if (!f.getType().isPrimitive()) {

                if (staticFieldsToo && isStatic) {
                    nullifyField(clazz, f);
                } else if (!isStatic && o != null) {
                    nullifyField(o, f);
                }
            }
        }
        nullifyFields(clazz.getSuperclass(), o, staticFieldsToo);
    }

    protected static void nullifyField(Class clazz, Field f) throws IllegalAccessException {
        boolean isStatic = Modifier.isStatic(f.getModifiers());
        boolean isFinal = Modifier.isFinal(f.getModifiers());
        if (isStatic && !isFinal) {
            Object value = f.get(clazz);
            if (value != null) {
                f.set(clazz, null);
            }
        }
    }

    protected static void nullifyField(Object o, Field f) throws IllegalAccessException {
        boolean isFinal = Modifier.isFinal(f.getModifiers());
        Object value = f.get(o);
        if (value != null && !isFinal) {
            f.set(o, null);
        }
    }

}
