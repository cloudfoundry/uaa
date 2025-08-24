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
package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.util.StringUtils;

public class Prompt {

    private final String name;
    private final String text;
    private final String type;

    @JsonCreator
    public Prompt(@JsonProperty("name") String name,
            @JsonProperty("type") String type,
            @JsonProperty("text") String text) {
        this.name = name;
        this.type = type;
        this.text = text;
    }

    public String getName() {
        return name;
    }

    public String getText() {
        return text;
    }

    public String getType() {
        return type;
    }

    @JsonIgnore
    public String[] getDetails() {
        return new String[]{type, text};
    }

    public static Prompt valueOf(String text) {
        if (!StringUtils.hasText(text)) {
            return null;
        }
        String[] parts = text.split(":");
        if (parts.length < 2) {
            return null;
        }
        String name = parts[0].replaceAll("\"", "");
        String[] values = parts[1].replaceAll("\"", "").replaceAll("\\[", "").replaceAll("\\]", "").split(",");
        values = StringUtils.trimArrayElements(values);
        return new Prompt(name, values[0], values[1]);
    }

    @Override
    public String toString() {
        return "\"%s\":[\"%s\",\"%s\"]".formatted(name, type, text);
    }

    @Override
    public int hashCode() {
        return 31 + toString().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        Prompt other = (Prompt) obj;
        return toString().equals(other.toString());
    }

}
