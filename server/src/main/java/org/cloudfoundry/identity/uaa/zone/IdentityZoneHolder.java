package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManager;
import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactory;
import org.springframework.beans.factory.annotation.Qualifier;

import java.util.Optional;

/**
 * Handles getting and caching of the current IdentityZone and its SamlKeyManager within ThreadLocal storage.
 *
 * @deprecated Use {@link org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager} instead, which still uses this class as a utility.
 */
@Deprecated(since = "4.29.0")
public final class IdentityZoneHolder {

    private IdentityZoneHolder() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    private static IdentityZoneProvisioning provisioning;
    private static SamlKeyManagerFactory samlKeyManagerFactory;

    public static void setProvisioning(IdentityZoneProvisioning provisioning) {
        IdentityZoneHolder.provisioning = provisioning;
    }

    public static void setSamlKeyManagerFactory(SamlKeyManagerFactory samlKeyManagerFactory) {
        IdentityZoneHolder.samlKeyManagerFactory = samlKeyManagerFactory;
    }

    private static final ThreadLocal<IdentityZone> IDENTITY_ZONE_THREAD_LOCAL =
            ThreadLocal.withInitial(() -> getUaaZone(provisioning));

    public static IdentityZone get() {
        return IDENTITY_ZONE_THREAD_LOCAL.get();
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
        KEY_MANAGER_THREAD_LOCAL.remove();
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

    private static final ThreadLocal<SamlKeyManager> KEY_MANAGER_THREAD_LOCAL =
            ThreadLocal.withInitial(() -> null);

    public static SamlKeyManager getSamlKeyManager() {
        SamlKeyManager keyManager = KEY_MANAGER_THREAD_LOCAL.get();
        if (keyManager != null) {
            return keyManager;
        }

        var optionalZoneSamlConfig = Optional.ofNullable(get())
                .map(IdentityZone::getConfig)
                .map(IdentityZoneConfiguration::getSamlConfig);
        boolean zoneHasKeys = optionalZoneSamlConfig.map(SamlConfig::getKeys)
                .map(k -> !k.isEmpty())
                .orElse(false);

        if (zoneHasKeys) {
            keyManager = samlKeyManagerFactory.getKeyManager(optionalZoneSamlConfig.orElse(null));
            setSamlKeyManager(keyManager);
            return keyManager;
        }

        var optionalUaaSamlConfig = Optional.ofNullable(getUaaZone(provisioning))
                .map(IdentityZone::getConfig)
                .map(IdentityZoneConfiguration::getSamlConfig)
                .orElse(null);

        keyManager = samlKeyManagerFactory.getKeyManager(optionalUaaSamlConfig);
        setSamlKeyManager(keyManager);
        return keyManager;
    }

    private static void setSamlKeyManager(SamlKeyManager keyManager) {
        KEY_MANAGER_THREAD_LOCAL.set(keyManager);
    }

    /**
     * Utility class to initialize the IdentityZoneHolder with the necessary dependencies.
     * Work around for the fact that IdentityZoneHolder is a static utility class and cannot be instantiated.
     */
    public static class Initializer {
        public Initializer(@Qualifier("identityZoneProvisioning") IdentityZoneProvisioning provisioning, SamlKeyManagerFactory samlKeyManagerFactory) {
            IdentityZoneHolder.setProvisioning(provisioning);
            IdentityZoneHolder.setSamlKeyManagerFactory(samlKeyManagerFactory);
        }

        public void reset() {
            IdentityZoneHolder.setProvisioning(null);
            IdentityZoneHolder.setSamlKeyManagerFactory(null);
        }
    }
}
