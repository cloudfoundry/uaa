/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.HashSet;
import java.util.List;

public class UserInfo {

    @JsonProperty("roles")
    private List<String> roles;
    @JsonProperty("user_attributes")
    private LinkedMultiValueMap<String, String> userAttributes;

    public UserInfo() {
    }


    @JsonIgnore
    public UserInfo setRoles(List<String> roles) {
        this.roles = roles;
        return this;
    }

    @JsonIgnore
    public List<String> getRoles() {
        return roles;
    }

    @JsonIgnore
    public UserInfo setUserAttributes(MultiValueMap<String, String> userAttributes) {
        this.userAttributes = new LinkedMultiValueMap<>(userAttributes);
        return this;
    }

    @JsonIgnore
    public MultiValueMap<String, String> getUserAttributes() {
        return userAttributes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserInfo)) {
            return false;
        }

        UserInfo userInfo = (UserInfo) o;

        if (!compareRoles(getRoles(), ((UserInfo) o).getRoles())) {
            return false;
        }
        return getUserAttributes() != null ? getUserAttributes().equals(userInfo.getUserAttributes()) : userInfo.getUserAttributes() == null;
    }

    protected boolean compareRoles(List<String> l1, List<String> l2) {
        if (l1 == null || l2 == null) {
            return l1 == l2;
        }
        return new HashSet<>(l1).equals(new HashSet<>(l2));
    }

    @Override
    public int hashCode() {
        int result = getRoles() != null ? getRoles().hashCode() : 0;
        result = 31 * result + (getUserAttributes() != null ? getUserAttributes().hashCode() : 0);
        return result;
    }
}
