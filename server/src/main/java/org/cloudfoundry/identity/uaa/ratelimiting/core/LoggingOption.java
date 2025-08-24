package org.cloudfoundry.identity.uaa.ratelimiting.core;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Consumer;

public enum LoggingOption {
    OnlyLimited() { // Default - see below //NOSONAR
        public static final String PREFIX = "Rate Limited path"; // public for reflection in tests
        public static final String SUFFIX = "->";

        @Override
        public void log(String requestPath, Consumer<String> logger, Instant startTime, Limiter limiter, Instant endTime) {
            if (limiter.shouldLimit()) {
                logger.accept(prefixAndPath(PREFIX, requestPath)
                        .append(SUFFIX).append(' ').append(limiter.getLimitingKey())
                        .toString());
            }
        }
    },
    AllCalls() { //NOSONAR
        public static final String PREFIX = "path";
        public static final String SUFFIX_CALLS_LIMITED = "-- LIMITED by ->";
        public static final String SUFFIX_CALLS_NOT_LIMITED = "-- NOT limited";

        @Override
        public void log(String requestPath, Consumer<String> logger, Instant startTime, Limiter limiter, Instant endTime) {
            StringBuilder sb = prefixAndPath(PREFIX, requestPath);
            addDuration(sb, startTime, endTime);
            if (limiter.shouldLimit()) {
                sb.append(SUFFIX_CALLS_LIMITED).append(' ').append(limiter.getLimitingKey());
            } else {
                sb.append(SUFFIX_CALLS_NOT_LIMITED);
            }
            logger.accept(sb.toString());
        }
    },
    AllCallsWithDetails() { //NOSONAR
        public static final String PREFIX = "********************************** RateLimiter w/ path";
        public static final String SUFFIX = "->";

        @Override
        public void log(String requestPath, Consumer<String> logger, Instant startTime, Limiter limiter, Instant endTime) {
            logger.accept(prefixAndPath(PREFIX, requestPath)
                    .append(SUFFIX).append(' ').append(limiter)
                    .toString());
        }
    };

    public abstract void log(String requestPath, Consumer<String> logger, Instant startTime, Limiter limiter, Instant endTime);

    protected StringBuilder prefixAndPath(String prefix, String requestPath) {
        return new StringBuilder().append(prefix).append(" '").append(requestPath).append("' ");
    }

    public static LoggingOption valueFor(String value) {
        for (LoggingOption option : values()) {
            if (option.name().equalsIgnoreCase(value)) {
                return option;
            }
        }
        return null;
    }

    public static final LoggingOption DEFAULT = LoggingOption.OnlyLimited;

    public static LoggingOption deNull(LoggingOption option) {
        return Optional.ofNullable(option).orElse(DEFAULT);
    }

    // packageFriendly for testing
    static void addDuration(StringBuilder sb, Instant startTime, Instant endTime) {
        if ((startTime != null) && (endTime != null)) {
            sb.append('(').append(Duration.between(startTime, endTime).toNanos()).append("ns) ");
        }
    }
}
