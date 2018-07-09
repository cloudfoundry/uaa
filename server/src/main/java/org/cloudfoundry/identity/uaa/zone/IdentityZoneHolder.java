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

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static java.util.Optional.ofNullable;

public class IdentityZoneHolder {

    private static IdentityZoneProvisioning provisioning;

    public static void setProvisioning(IdentityZoneProvisioning provisioning) {
        IdentityZoneHolder.provisioning = provisioning;
    }

    private static final ThreadLocal<IdentityZoneWithKeyManager> THREADLOCAL = new InheritableThreadLocal<IdentityZoneWithKeyManager>() {
        @Override
        protected IdentityZoneWithKeyManager initialValue() {
            if (provisioning==null) {
                return new IdentityZoneWithKeyManager(IdentityZone.getUaa());
            }
            IdentityZone zone = getUaaZone();
            return new IdentityZoneWithKeyManager(zone);
        }
    };

    public static IdentityZone get() {
        return THREADLOCAL.get().getZone();
    }

    public static IdentityZone getUaaZone() {
        if (provisioning==null) {
            return IdentityZone.getUaa();
        }
        return provisioning.retrieve(IdentityZone.getUaa().getId());
    }

    public static void set(IdentityZone zone) {
        THREADLOCAL.set(new IdentityZoneWithKeyManager(zone));
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

        public void reset() {
            IdentityZoneHolder.setProvisioning(null);
        }
    }

    public static class IdentityZoneWithKeyManager {
        private IdentityZone zone;

        public IdentityZoneWithKeyManager(IdentityZone zone) {
            this.zone = zone;
        }

        public IdentityZone getZone() {
            return zone;
        }
    }

    private static class MergedZoneBrandingInformation implements BrandingInformationSource {
        @Override
        public BrandingInformation.Banner getBanner() {
            return resolve(BrandingInformationSource::getBanner);
        }

        @Override
        public String getCompanyName() {
            return resolve(BrandingInformationSource::getCompanyName);
        }

        @Override
        public String getProductLogo() {
            return tryGet(get(), BrandingInformationSource::getProductLogo).orElse(null);
        }

        @Override
        public String getSquareLogo() {
            return resolve(BrandingInformationSource::getSquareLogo);
        }

        @Override
        public String getFooterLegalText() {
            return resolve(BrandingInformationSource::getFooterLegalText);
        }

        @Override
        public Map<String, String> getFooterLinks() {
            return resolve(BrandingInformationSource::getFooterLinks);
        }

        private static <T> T resolve(Function<BrandingInformationSource, T> brandingProperty) {
            return
              tryGet(get(), brandingProperty)
                .orElse(tryGet(getUaaZone(), brandingProperty)
                  .orElse(null));
        }

        private static <T> Optional<T> tryGet(IdentityZone zone, Function<BrandingInformationSource, T> brandingProperty) {
            return ofNullable(zone.getConfig())
              .flatMap(c -> ofNullable(c.getBranding()))
                .flatMap(b -> ofNullable(brandingProperty.apply(b)));
        }
    }

    private static final BrandingInformationSource brandingResolver = new MergedZoneBrandingInformation();
    public static BrandingInformationSource resolveBranding() {
        return brandingResolver;
    }

}
