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
package org.cloudfoundry.identity.uaa.codestore;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Data;

import java.sql.Timestamp;
import java.util.Objects;

@Data
@JsonSerialize
@JsonDeserialize
public class ExpiringCode {

    private String code;

    private Timestamp expiresAt;

    private String data;

    private String intent;

    public ExpiringCode() {
    }

    public ExpiringCode(String code, Timestamp expiresAt, String data, String intent) {
        this.code = code;
        this.expiresAt = expiresAt;
        this.data = data;
        this.intent = intent;
    }

    @JsonIgnore
    public boolean isExpired() {
        if (expiresAt == null) {
            return false;
        }
        return expiresAt.getTime() < System.currentTimeMillis();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ExpiringCode that)) {
            return false;
        }

        if (!Objects.equals(code, that.code)) {
            return false;
        }
        if (!Objects.equals(data, that.data)) {
            return false;
        }
        return Objects.equals(expiresAt, that.expiresAt);
    }

    @Override
    public int hashCode() {
        return code != null ? code.hashCode() : 0;
    }

    @Override
    public String toString() {
        return "ExpiringCode [code=" + code + ", expiresAt=" + expiresAt + ", data=" + trimToLength(data) + ", intent=" + intent + "]";
    }

    private String trimToLength(String s) {
        int min = Math.min(s.length(), 1024);
        if (min == s.length()) {
            return s;
        } else {
            return s.substring(0, min);
        }
    }
}
