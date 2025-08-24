package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.LimiterMapping;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiPredicate;

import static org.assertj.core.api.Assertions.assertThat;

class PathFragmentToLimiterMappingsTest {

    private PathFragmentToLimiterMappings mapper;
    private Selector selector;

    @Test
    void noLimiterMappings() {
        mapper = new PathFragmentToLimiterMappings(String::contains);

        assertThat(mapper.isEmpty()).isTrue();
        assertThat(mapper.count()).isZero();
        assertThat(streamToPathFragments()).isEqualTo(List.of());

        assertThat(mapper.get("significantOther/Wilma/of/Fred")).isNull();
    }

    @Test
    void fewLimiterMappings() {
        PathFragmentToLimiterMapping fred = pftp("Fred");
        PathFragmentToLimiterMapping pebbles = pftp("Pebbles");
        PathFragmentToLimiterMapping wilma = pftp("Wilma");

        mapper = new PathFragmentToLimiterMappings(String::contains, fred, pebbles, wilma);

        assertThat(mapper.isEmpty()).isFalse();
        assertThat(mapper.count()).isEqualTo(3);
        assertThat(streamToPathFragments()).isEqualTo(List.of(pebbles, wilma, fred));

        assertThat(mapper.get("significantOther/Wilma/of/Fred")).isEqualTo(wilma.getLimiterMapping());
    }

    @Test
    void getCompares() {
        selector = new Selector();
        List<PathFragmentToLimiterMapping> pftps = new ArrayList<>();
        for (int i = 1; i <= 50; i++) {
            addTo(pftps, makePath('A', i));
            addTo(pftps, makePath('B', i));
        }
        mapper = new PathFragmentToLimiterMappings(selector, pftps);

        assertThat(check(false, "X")).isEqualTo(2);
        assertThat(check(false, makePath('X', 25))).isEqualTo(50);
        assertThat(check(false, makePath('X', 50))).isEqualTo(100);
        assertThat(check(true, makePath('B', 25))).isEqualTo(2);
    }

    private int check(boolean expectedFound, String servletPath) {
        selector.calls = 0;
        Instant start = Instant.now();
        LimiterMapping found = mapper.get(servletPath);
        int calls = selector.calls;
        System.out.println(Duration.between(start, Instant.now()).toNanos() + "ns: " + calls + " -> " + servletPath);
        if (expectedFound) {
            assertThat(found).isNotNull();
        } else {
            assertThat(found).isNull();
        }
        return calls;
    }

    private void addTo(List<PathFragmentToLimiterMapping> collection, String pathFragmentAndName) {
        collection.add(pftp(pathFragmentAndName));
    }

    private static String makePath(char letter, int count) {
        StringBuilder sb = new StringBuilder(count);
        while (0 < count--) {
            sb.append(letter);
        }
        return sb.toString();
    }

    private static class Selector implements BiPredicate<String, String> {
        int calls;

        @Override
        public boolean test(String servletPath, String pathFragment) {
            calls++;
            return servletPath.equals(pathFragment); // using equals just for testing!
        }
    }

    private static PathFragmentToLimiterMapping pftp(String pathFragmentAndName) {
        return new PathFragmentToLimiterMapping(pathFragmentAndName,
                LimiterMapping.builder()
                        .name(pathFragmentAndName)
                        .pathSelector("contains:" + pathFragmentAndName)
                        .global("1r/s")
                        .build());
    }

    private List<PathFragmentToLimiterMapping> streamToPathFragments() {
        return mapper.stream().toList();
    }
}