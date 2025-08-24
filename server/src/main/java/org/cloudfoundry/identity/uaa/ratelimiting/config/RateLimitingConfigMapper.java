package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;

public interface RateLimitingConfigMapper {
    RateLimitingFactoriesSupplierWithStatus map(RateLimitingFactoriesSupplierWithStatus current, String fromSource, YamlConfigFileDTO dto);
}
