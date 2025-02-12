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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public final class ObjectUtils {

    private ObjectUtils() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static <T> T castInstance(Object o, Class<T> clazz) {
        try {
            return clazz.cast(o);
        } catch (ClassCastException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
        factory.setFeature("http://xml.org/sax/features/validation", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setValidating(false);
        factory.setNamespaceAware(true);
        factory.setExpandEntityReferences(false);
        return factory.newDocumentBuilder();
    }

    public static int countNonNull(Object... objects) {
        int count = 0;
        if (objects != null) {
            for (Object o : objects) {
                if (o != null) {
                    count++;
                }
            }
        }
        return count;
    }

    public static boolean isEmpty(final Object object) {
        return org.springframework.util.ObjectUtils.isEmpty(object);
    }

    public static boolean isNotEmpty(Object object) {
        return !isEmpty(object);
    }
}
