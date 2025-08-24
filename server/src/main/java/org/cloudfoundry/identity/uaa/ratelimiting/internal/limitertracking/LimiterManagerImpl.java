package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import lombok.NonNull;
import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.Limiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LimiterManager;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.RequestsPerWindowSecs;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.LimiterFactorySupplierUpdatable;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.LimiterImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.Singleton;

public class LimiterManagerImpl implements LimiterManager,
        LimiterFactorySupplierUpdatable {
    public static final Singleton<LimiterManagerImpl> SINGLETON =
            new Singleton<>( () -> new LimiterManagerImpl( null ) );

    private final LimiterByCompoundKey limiterByCompoundKey; // dynamically managed!
    private final ExpirationBuckets expirationBuckets;
    private volatile RateLimitingFactoriesSupplierWithStatus supplierAndStatus; //NOSONAR - RateLimitingFactoriesSupplierWithStatus is immutable, so sync on the field is sufficient
    private Thread backgroundThread;

    // package friendly for testing
    InternalLimiterFactoriesSupplier getFactorySupplier() {
        return supplierAndStatus.getSupplier();
    }

    @Override
    public String rateLimitingStatus() {
        return supplierAndStatus.getStatusJson();
    }

    @Override
    public Limiter getLimiter(RequestInfo info) {
        // Due to the volatile nature of limiterFactorySupplier - all work should occur from a single reference to it!
        InternalLimiterFactoriesSupplier supplier = getFactorySupplier();
        return createLimiter(generateLimiterList(info, supplier), supplier.getLoggingOption());
    }

    @Override
    public void update(@NonNull RateLimitingFactoriesSupplierWithStatus supplierAndStatus) {
        this.supplierAndStatus = supplierAndStatus;
    }

    /**
     * Generate a list of Internal Limiters (1-n).
     * <p>
     * Note: the list of <code>InternalLimiter</code> must be appropriately ordered, which means:<ul>
     * <li>Consistent - every pair of <code>InternalLimiter</code> (based on the combination of name and limiting type) should always be in the same order</li>
     * <li>Frequency (of list membership) try for least to most - <code>globals</code> (not using any caller ID) should be later in the list</li>
     * </ul>
     * <p>
     * Note-2: Consistent ordering ensures no Dead Locks when creating the exclusive access for each entry in order.
     * <p>
     * Note-3: Frequency order is immaterial, if no limiting is indicated, as every <code>InternalLimiter</code> must be checked.
     * However, if any <code>InternalLimiter</code>, before the last one, indicates limiting, then subsequent <code>InternalLimiter</code>(s)
     * are not involved, and they are not seized for exclusive access.
     * <p>
     * Note-3: Special Scenario - where no internal limiter factories returned:<ul>
     * <li>no "all"</li>
     * <li>path-based selected, but only withCallerCredentialsID and no CredentialID</li>
     * <li>"other" exists but superseded by path-based</li>
     * </ul>
     */
    // package protected for testing
    List<InternalLimiter> generateLimiterList(RequestInfo info, InternalLimiterFactoriesSupplier supplier) {
        Map<CompoundKey, InternalLimiterFactory> factoryMap = supplier.factoryMapFor(info);
        if ((factoryMap == null) || factoryMap.isEmpty()) { // null (NOOP version); empty (special scenario)
            return null; //NOSONAR
        }
        List<InternalLimiter> limiters = new ArrayList<>( factoryMap.size() );
        for (Map.Entry<CompoundKey, InternalLimiterFactory> entry : factoryMap.entrySet()) { // Priority/Lock order!
            limiters.add(limiterByCompoundKey.get(entry.getKey(), entry.getValue(), expirationBuckets));
        }
        return limiters;
    }

    /**
     * Create and return a Limiter - either a <code>Limiter.FORWARD_REQUEST</code> which indicates limiting is effectively disabled OR a <code>LimiterImpl</code>.
     * <p>
     * Note: If <code>LimiterImpl</code> indicates limiting, then none of the InternalLimiter(s) should have their <code>requestsRemaining</code> reduced
     * Note: If <code>LimiterImpl</code> indicates NOT limiting, then ALL the InternalLimiter(s) should have their <code>requestsRemaining</code> reduced
     *
     * @param limiters      null or a non empty list of <code>InternalLimiter</code>(s)
     * @param loggingOption a non-Null enum that indicates the logging approach
     * @return either <code>Limiter.FORWARD_REQUEST</code> or a <code>LimiterImpl</code>
     */
    // package protected for testing
    Limiter createLimiter(List<InternalLimiter> limiters, @NonNull LoggingOption loggingOption) { // null or not empty
        return limiters == null ? Limiter.FORWARD_REQUEST : LimiterImpl.from(limiters, loggingOption);
    }

    @Override
    public synchronized void startBackgroundProcessing() {
        if (backgroundThread == null) {
            backgroundThread = new Thread( expirationBuckets );
            backgroundThread.setName("LimiterExpirationProcess");
            backgroundThread.setDaemon(true);
            backgroundThread.start();
        }
    }

    @Override
    public synchronized void shutdownBackgroundProcessing() {
        expirationBuckets.die();
        if (backgroundThread != null) {
            backgroundThread.interrupt();
            backgroundThread = null;
        }
    }

    // package protected for testing
    LimiterManagerImpl(NanoTimeSupplier currentTimeSupplier) {
        currentTimeSupplier = NanoTimeSupplier.deNull(currentTimeSupplier);
        limiterByCompoundKey = new LimiterByCompoundKey( currentTimeSupplier );
        expirationBuckets = new ExpirationBuckets( currentTimeSupplier, limiterByCompoundKey,
                RequestsPerWindowSecs.MAX_WINDOW_SECONDS );
        supplierAndStatus = RateLimitingFactoriesSupplierWithStatus.builder()
                .supplier(InternalLimiterFactoriesSupplier.NOOP)
                .status(RateLimiterStatus.builder()
                        .current(RateLimiterStatus.Current.builder()
                                .status(RateLimiterStatus.CurrentStatus.DISABLED)
                                .asOf(TimeUnit.NANOSECONDS.toMillis(currentTimeSupplier.now()))
                                .build())
                        .build())
                .build();
    }

    // package protected for testing
    void processExpirations() {
        expirationBuckets.processExpirations();
    }
}
