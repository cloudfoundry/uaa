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
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;

public class UserInfo extends LinkedMultiValueMap<String,String> implements MultiValueMap<String, String> {

    public UserInfo(){}

    @JsonIgnore
    public UserInfo(MultiValueMap<String, String> map) {
        super(map);
    }

    @JsonIgnore
    public void put(String name, String value) {
        put(name, Arrays.asList(value));
    }


}
