/*******************************************************************************
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
package org.cloudfoundry.identity.uaa.zone;

public class IdentityZoneHolder {

    private static final ThreadLocal<IdentityZone> THREADLOCAL = new InheritableThreadLocal<IdentityZone>() {
        @Override
        protected IdentityZone initialValue() {
            return IdentityZone.getUaa();
        }
    };

    public static IdentityZone get() {
        return THREADLOCAL.get();
    }

    public static void set(IdentityZone zone) {
        THREADLOCAL.set(zone);
    }

    public static void clear() {
        THREADLOCAL.remove();
    }
    
    public static boolean isUaa() {
        return THREADLOCAL.get().getId().equals(IdentityZone.getUaa().getId());
    }

}
