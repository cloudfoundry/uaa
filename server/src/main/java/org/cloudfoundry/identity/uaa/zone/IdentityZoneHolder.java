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

    private static final ThreadLocal<IdentityZoneWithKeyManager> THREADLOCAL = new InheritableThreadLocal<IdentityZoneWithKeyManager>() {
        @Override
        protected IdentityZoneWithKeyManager initialValue() {
            if (provisioning==null) {
                return new IdentityZoneWithKeyManager(IdentityZone.getUaa(), null);
            }
            IdentityZone zone = getUaaZone();
            return new IdentityZoneWithKeyManager(zone, null);
        }
    };

    public static IdentityZone get() {
        return THREADLOCAL.get().getZone();
    }

    public static KeyManager getSamlSPKeyManager() {
        IdentityZoneWithKeyManager withKeyManager = THREADLOCAL.get();
        if (withKeyManager.getManager()==null) {
            KeyManager keyManager = SamlKeyManagerFactory.getKeyManager(withKeyManager.getZone().getConfig().getSamlConfig());
            if (keyManager==null) {
                keyManager = SamlKeyManagerFactory.getKeyManager(getUaaZone().getConfig().getSamlConfig());
            }
            withKeyManager.setManager(keyManager);
        }
        return withKeyManager.getManager();
    }

    public static IdentityZone getUaaZone() {
        if (provisioning==null) {
            return IdentityZone.getUaa();
        }
        return provisioning.retrieve(IdentityZone.getUaa().getId());
    }

    public static void set(IdentityZone zone) {
        THREADLOCAL.set(new IdentityZoneWithKeyManager(zone, null));
    }

    public static void clear() {
        THREADLOCAL.remove();
    }
    
    public static boolean isUaa() {
        return THREADLOCAL.get().getZone().getId().equals(IdentityZone.getUaa().getId());
    }

    public static class Initializer {
        public Initializer(IdentityZoneProvisioning provisioning) {
            IdentityZoneHolder.setProvisioning(provisioning);
        }
    }

    public static class IdentityZoneWithKeyManager {
        private IdentityZone zone;
        private KeyManager manager;

        public IdentityZoneWithKeyManager(IdentityZone zone, KeyManager manager) {
            this.zone = zone;
            this.manager = manager;
        }

        public IdentityZone getZone() {
            return zone;
        }

        public KeyManager getManager() {
            return manager;
        }

        public void setManager(KeyManager manager) {
            this.manager = manager;
        }
    }

}
