package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactory;
import org.springframework.security.saml.key.KeyManager;

/**
 * @Deprecated Use {@link org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager} instead
 */
@Deprecated
public class IdentityZoneHolder {

    private static IdentityZoneProvisioning provisioning;

    public static void setProvisioning(IdentityZoneProvisioning provisioning) {
        IdentityZoneHolder.provisioning = provisioning;
    }

    private static SamlKeyManagerFactory samlKeyManagerFactory = new SamlKeyManagerFactory();

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

        keyManager = samlKeyManagerFactory.getKeyManager(IDENTITY_ZONE_THREAD_LOCAL.get().getConfig().getSamlConfig());
        if (keyManager != null) {
            KEY_MANAGER_THREAD_LOCAL.set(keyManager);
            return keyManager;
        }

        keyManager = samlKeyManagerFactory.getKeyManager(getUaaZone(provisioning).getConfig().getSamlConfig());
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
        return IDENTITY_ZONE_THREAD_LOCAL.get().isUaa();
    }

    public static String getCurrentZoneId() {
        return IDENTITY_ZONE_THREAD_LOCAL.get().getId();
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
