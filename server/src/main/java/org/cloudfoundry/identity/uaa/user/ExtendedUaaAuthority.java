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
package org.cloudfoundry.identity.uaa.user;

import java.util.Map;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;

@SuppressWarnings("serial")
public class ExtendedUaaAuthority implements GrantedAuthority {

    private String authority;

    private Map<String, String> additionalInfo;

    public ExtendedUaaAuthority(String authority, Map<String, String> additionalInfo) {
        this.authority = authority;
        this.additionalInfo = additionalInfo;
    }

    @Override
    public String getAuthority() {
        return authority;
    }

    public Map<String, String> getAdditionalInfo() {
        return additionalInfo;
    }

    @Override
    public String toString() {
        return authority;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof ExtendedUaaAuthority)) {
            return false;
        }

        ExtendedUaaAuthority e = (ExtendedUaaAuthority) obj;
        return Objects.equals(e.getAuthority(), authority) && e.additionalInfo.equals(additionalInfo);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

}
