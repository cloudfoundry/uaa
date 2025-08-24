package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import java.util.LinkedHashMap;

import jakarta.validation.constraints.NotNull;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;

public interface InternalLimiterFactoriesSupplier {
    /**
     * Convert some <code>InternalLimiterFactory</code>(s) into appropriate <code>compoundKey</code> to factory map.
     * <p>
     * Note: the (ordered iteration) map of <code>InternalLimiter</code> must be appropriately ordered, which means:<ul>
     * <li>Consistent - every pair of <code>InternalLimiter</code> (based on the combination of name and limiting type) should always be in the same order</li>
     * <li>Frequency (of list membership) try for least to most - <code>globals</code> (not using any caller ID) should be later in the list</li>
     * </ul>
     * <p>
     * Note-2: Consistent ordering ensures no Dead Locks when creating the exclusive access for each entry in order.
     * <p>
     * Note-3: Frequency order is immaterial, if no limiting is indicated, as every <code>InternalLimiter</code> must be checked.
     * However, if any <code>InternalLimiter</code>, before the last one, indicates limiting, then subsequent <code>InternalLimiter</code>(s)
     * are not involved, and they are not seized for exclusive access.
     *
     * @param info used to extract the <code>path</code> and supply caller IDs based on the available <code>InternalLimiterFactory</code>
     * @return LinkedHashMapMap (ordered iteration) of <code>InternalLimiterFactory</code> by <code>compoundKey</code>, in locking order (non-Global -> Global)
     */
    LinkedHashMap<CompoundKey, InternalLimiterFactory> factoryMapFor(RequestInfo info);

    @NotNull
    default LoggingOption getLoggingOption() {
        return LoggingOption.DEFAULT;
    }

    default boolean isSupplierNOOP() {
        return true;
    }

    default String getCallerCredentialsIdSupplierDescription() {
        return "NOOP";
    }

    default int getLimiterMappings() {
        return 0;
    }

    InternalLimiterFactoriesSupplier NOOP = info -> null;

    static InternalLimiterFactoriesSupplier deNull(InternalLimiterFactoriesSupplier supplier) {
        return supplier != null ? supplier : NOOP;
    }
}
