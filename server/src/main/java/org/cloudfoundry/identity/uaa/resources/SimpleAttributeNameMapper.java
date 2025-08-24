/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.resources;

import java.util.Collections;
import java.util.Map;

public class SimpleAttributeNameMapper implements AttributeNameMapper {

    private Map<String, String> paramsMap = Collections.emptyMap();

    public SimpleAttributeNameMapper(Map<String, String> paramsMap) {
        this.paramsMap = paramsMap;
    }

    @Override
    public String mapToInternal(String attr) {
        String mappedAttr = attr;
        for (Map.Entry<String, String> entry : paramsMap.entrySet()) {
            mappedAttr = mappedAttr.replaceAll(entry.getKey(), entry.getValue());
        }
        return mappedAttr;
    }

    @Override
    public String mapFromInternal(String attr) {
        String mappedAttr = attr;
        for (Map.Entry<String, String> entry : paramsMap.entrySet()) {
            mappedAttr = mappedAttr.replaceAll(entry.getValue(), entry.getKey());
        }
        return mappedAttr;
    }
}
