package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.LimiterMapping;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.junit.jupiter.api.Test;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class LimiterManagerImplTest {

    static final List<LimiterMapping> allAndPathBasedLimiterMappings = List.of(
            LimiterMapping.builder().name("F1").pathSelector("equals:/F1").withCallerCredentialsID("2r/s").build(),
            LimiterMapping.builder().name("F2").pathSelector("equals:/F2").withCallerCredentialsID("4r/2s").build(),
            LimiterMapping.builder().name("F3").pathSelector("equals:/F3").global("8r/4s").build(),
            LimiterMapping.builder().name("GB").pathSelector("All").global("74r/8s").build());

    private void allAndPathBasedCalls() {
        call("/F1", "K1");
        call("/F1", "K2");
        call("/F2", "K1");
        call("/F2", "K2");
        call("/F3", "??");
    }

    // The combinatorics of the above should generate the following results. As the "All" InternalLimiter is only called
    // if the non-All (which is called first) doesn't limit, the "All" InternalLimiter is not directly shown below.
    // The "All" InternalLimiter is reflected in the results below starting at time '6.750' secs for "F2" and "K1"!
    private void allAndPathBasedCheckResults() {
        assertThat(instanceTracking).hasSize(6); // 5 plus the GBs
        // . .  0...1...2...3...4...5...6...7...8 seconds with calls every 250ms
        check("NFLLNFLLNFLLNFLLNFLLNFLLNFLLnLLL", "F1", "K1");
        check("NFLLNFLLNFLLNFLLNFLLNFLLNFLLnLLL", "F1", "K2");
        check("NFFFLLLLNFFFLLLLNFFFLLLLNFFLLLLL", "F2", "K1");
        check("NFFFLLLLNFFFLLLLNFFFLLLLNFFLLLLL", "F2", "K2");
        check("NFFFFFFFLLLLLLLLNFFFFFFFLLLLLLLL", "F3", WindowType.GLOBAL.cannedCallerID());
    }

    static final String[] INITIAL_STATUS = {
            "{",
            "  'current' : {",
            "    'status' : 'DISABLED',",
            "    'asOf' : '2000-01-01T00:00:00Z'",
            "  }",
            "}"
    };

    @Test
    void initialState() {
        servletPath = "/info";
        assertThat(lm.getLimiter(requestInfo).shouldLimit()).isFalse();
        assertThat(lm.rateLimitingStatus()).isEqualTo(String.join("\n", INITIAL_STATUS).replace('\'', '"'));
    }

    @Test
    void interactionOfAllAndPathBasedLimiter() {
        runSet(allAndPathBasedLimiterMappings,
                this::allAndPathBasedCalls,
                this::allAndPathBasedCheckResults);
    }

    static final List<LimiterMapping> interactionOfMultiPathBasedLimiterMappings = List.of(
            LimiterMapping.builder().name("FF").pathSelectors("equals:/F1", "equals:/F2").withCallerCredentialsID("4r/s").build(),
            LimiterMapping.builder().name("GB").pathSelector("All").global("999r/8s").build()); // So can ignore

    private void interactionOfMultiPathBasedCalls() {
        call("/F1", "K1"); // first two calls should count against the same Limiter/CallerID (FF & K1)
        call("/F2", "K1");
        call("/F1", "K2"); // last two calls should count against the same Limiter/CallerID (FF & K2)
        call("/F2", "K2");
    }

    // The combinatorics of the above should generate the following results. As the "All" InternalLimiter is only called
    // if the non-All (which is called first) doesn't limit, the "All" InternalLimiter is not directly shown below.
    // The "All" InternalLimiter is NOT reflected in the results below as its limit is never reached!
    private void interactionOfMultiPathBasedCheckResults() {
        assertThat(instanceTracking).hasSize(3); // 2 plus the GBs
        // . .  0 . . . 1 . . . 2 . . . 3 . . . 4 . . . 5 . . . 6 . . . 7 . . . 8 seconds with TWO calls every 250ms
        check("NFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLL", "FF", "K1");
        check("NFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLL", "FF", "K2");
    }

    @Test
    void interactionOfMultiPathSelectorLimiter() {
        runSet(interactionOfMultiPathBasedLimiterMappings,
                this::interactionOfMultiPathBasedCalls,
                this::interactionOfMultiPathBasedCheckResults);
    }

    void runSet(List<LimiterMapping> limiterMappings, Runnable calls, Runnable checkResults) {
        lm.update(RateLimitingFactoriesSupplierWithStatus.builder()
                .supplier(new InternalLimiterFactoriesSupplierImpl(credentialIdExtractor, null, limiterMappings))
                .build());
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 4; j++) {
                calls.run();
                mTS.add(250000000); // 250ms
                lm.processExpirations();
            }
        }
        checkResults.run();
    }

    NanoTimeSupplier.Mock mTS = new NanoTimeSupplier.Mock(Instant.parse("2000-01-01T00:00:00Z"));

    LimiterManagerImpl lm = new LimiterManagerImpl(mTS);

    MultiValueMap<String, Character> results = new LinkedMultiValueMap<>();

    Map<CompoundKey, InternalLimiter> instanceTracking = new LinkedHashMap<>();

    private void recordCall(List<InternalLimiter> iLimiters) {
        boolean limit = lm.createLimiter(iLimiters, LoggingOption.DEFAULT).shouldLimit();
        for (InternalLimiter currentLimiter : iLimiters) {
            CompoundKey compoundKey = currentLimiter.getCompoundKey();
            String resultsKey = resultsKey(compoundKey);
            boolean isNew = currentLimiter != instanceTracking.get(compoundKey);
            if (isNew) {
                instanceTracking.put(compoundKey, currentLimiter);
                results.add(resultsKey, limit ? 'n' : 'N');
            } else {
                results.add(resultsKey, limit ? 'L' : 'F');
            }
        }
    }

    String callerID;
    String servletPath;

    AuthorizationCredentialIdExtractor credentialIdExtractor = info -> callerID;

    RequestInfo requestInfo = new RequestInfo() {
        @Override
        public String getClientIP() {
            return null;
        }

        @Override
        public String getAuthorizationHeader() {
            return "whatever";
        }

        @Override
        public String getServletPath() {
            return servletPath;
        }
    };

    private void call(String servletPath, String callerID) {
        this.servletPath = servletPath;
        this.callerID = callerID;
        recordCall(lm.generateLimiterList(requestInfo, lm.getFactorySupplier()));
    }

    private void check(String expectedResult, String limiterName, String callerID) {
        String instanceKey = resultsKey(limiterName, callerID);
        String actualResult = compress(results.get(instanceKey));
        assertThat(actualResult).as(instanceKey).isEqualTo(expectedResult);
    }

    private static String compress(List<Character> chars) {
        StringBuilder sb = new StringBuilder(chars.size());
        for (Character chr : chars) {
            sb.append(chr);
        }
        return sb.toString();
    }

    static String resultsKey(String limiterName, String callerID) {
        return limiterName + "|" + callerID;
    }

    static String resultsKey(CompoundKey compoundKey) {
        return resultsKey(compoundKey.getLimiterName(), compoundKey.getCallerID());
    }
}