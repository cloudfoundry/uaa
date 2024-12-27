package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import lombok.Builder;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtilities;

public class RateLimitingFactoriesSupplierWithStatus {
    public static final RateLimitingFactoriesSupplierWithStatus NO_RATE_LIMITING =
            RateLimitingFactoriesSupplierWithStatus.builder()
                    // No InternalLimiterFactoriesSupplier -> NO_RATE_LIMITING
                    .status(RateLimiterStatus.NO_RATE_LIMITING).build();

    private final InternalLimiterFactoriesSupplier supplier;
    private final RateLimiterStatus status;
    private final String statusJson;

    @Builder(toBuilder = true)
    public RateLimitingFactoriesSupplierWithStatus(InternalLimiterFactoriesSupplier supplier, RateLimiterStatus status) {
        this.supplier = supplier;
        this.status = status;
        statusJson = status == null ? null : status.toString();
    }

    public InternalLimiterFactoriesSupplier getSupplier() {
        return supplier;
    }

    public RateLimiterStatus getStatus() {
        return status;
    }

    public boolean isRateLimitingEnabled() {
        return getSupplier() != null;
    }

    public String getStatusJson() {
        return statusJson;
    }

    public boolean hasStatusCurrentSection() {
        return (status != null) && status.hasCurrentSection();
    }

    public RateLimitingFactoriesSupplierWithStatus updateError(Exception e) {
        return e == null ? this : toBuilder().status(ensureStatus()).build();
    }

    public RateLimitingFactoriesSupplierWithStatus update() {
        return toBuilder().status(ensureStatus()).build();
    }

    public static RateLimitingFactoriesSupplierWithStatus create(InternalLimiterFactoriesSupplier supplier, String errorMsg,
            long asOf, String fromSource) {
        return builder().supplier(supplier).status(RateLimiterStatus.create(supplier, errorMsg, asOf, fromSource)).build();
    }

    private RateLimiterStatus ensureStatus() {
        return status != null ? status : RateLimiterStatus.NO_RATE_LIMITING;
    }
}
