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

import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactory;
import org.springframework.security.saml.key.KeyManager;

public class IdentityZoneHolder {

    private static IdentityZoneProvisioning provisioning;

    public static void setProvisioning(IdentityZoneProvisioning provisioning) {
        IdentityZoneHolder.provisioning = provisioning;
    }

    private static final ThreadLocal<IdentityZone> IDENTITY_ZONE_THREAD_LOCAL = InheritableThreadLocal
            .withInitial(() -> getUaaZone(provisioning));

    public static IdentityZone get() {
        return IDENTITY_ZONE_THREAD_LOCAL.get();
    }

    private static final ThreadLocal<KeyManager> KEY_MANAGER_THREAD_LOCAL = InheritableThreadLocal.withInitial(() -> null);

    public static KeyManager getSamlSPKeyManager() {
        KeyManager keyManager = KEY_MANAGER_THREAD_LOCAL.get();
        if (keyManager != null) {
            return keyManager;
        }

        keyManager = SamlKeyManagerFactory.getKeyManager(IDENTITY_ZONE_THREAD_LOCAL.get().getConfig().getSamlConfig());
        if (keyManager != null) {
            KEY_MANAGER_THREAD_LOCAL.set(keyManager);
            return keyManager;
        }

        keyManager = SamlKeyManagerFactory.getKeyManager(getUaaZone(provisioning).getConfig().getSamlConfig());
        KEY_MANAGER_THREAD_LOCAL.set(keyManager);
        return keyManager;
    }

    public static IdentityZone getUaaZone() {
        return getUaaZone(provisioning);
    }

    private static IdentityZone getUaaZone(IdentityZoneProvisioning provisioning) {
        if (provisioning == null) {
            return IdentityZone.getUaa();
        }
        return provisioning.retrieve(IdentityZone.getUaaZoneId());
    }

    public static void set(IdentityZone zone) {
        IDENTITY_ZONE_THREAD_LOCAL.set(zone);
        KEY_MANAGER_THREAD_LOCAL.set(null);
    }

    public static void clear() {
        IDENTITY_ZONE_THREAD_LOCAL.remove();
        KEY_MANAGER_THREAD_LOCAL.remove();
    }

    public static boolean isUaa() {
        return IDENTITY_ZONE_THREAD_LOCAL.get().getId().equals(IdentityZone.getUaaZoneId());
    }

    public static class Initializer {
        public Initializer(IdentityZoneProvisioning provisioning) {
            IdentityZoneHolder.setProvisioning(provisioning);
        }

        public void reset() {
            IdentityZoneHolder.setProvisioning(null);
        }
    }
}
