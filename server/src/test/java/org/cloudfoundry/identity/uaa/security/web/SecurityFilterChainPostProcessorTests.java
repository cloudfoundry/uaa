package org.cloudfoundry.identity.uaa.security.web;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityFilterChainPostProcessorTests {

    private final SecurityFilterChainPostProcessor processor = new SecurityFilterChainPostProcessor();
    private SecurityFilterChain fc;
    private final Map<SecurityFilterChainPostProcessor.FilterPosition, Filter> additionalFilters = new HashMap<>();
    private int count;

    @BeforeEach
    void setUp() {
        List<Filter> filters = new LinkedList<>();
        filters.add(new TestFilter1());
        filters.add(new TestFilter2());
        filters.add(new TestFilter3());
        fc = mock(SecurityFilterChain.class);
        when(fc.getFilters()).thenReturn(filters);
        count = filters.size() + 1;
    }

    @AfterEach
    void tearDown() {

    }

    private void testPositionFilter(int pos) {
        int expectedPos = pos > count ? count : pos + 1;
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(pos), new PositionFilter());
        processor.setAdditionalFilters(additionalFilters);
        processor.postProcessAfterInitialization(fc, "");
        assertThat(fc.getFilters()).hasSize(count + 1);
        assertThat(fc.getFilters().get(expectedPos).getClass()).as("filter[%d] should be:%s".formatted(pos, PositionFilter.class.getSimpleName())).isEqualTo(PositionFilter.class);
    }

    @Test
    void position0Filter() {
        testPositionFilter(0);
    }

    @Test
    void position1Filter() {
        testPositionFilter(1);
    }

    @Test
    void positionLastFilter() {
        testPositionFilter(Integer.MAX_VALUE);
    }

    private void testClassPlacementFilter(Class<?> clazz, int expectedPosition) {
        processor.setAdditionalFilters(additionalFilters);
        processor.postProcessAfterInitialization(fc, "");
        assertThat(fc.getFilters()).hasSize(count + 1);
        assertThat(clazz).as("filter[%s] should be at position:%d".formatted(clazz.getSimpleName(), expectedPosition)).isEqualTo(fc.getFilters().get(expectedPosition).getClass());
    }

    @Test
    void beforePlacement1() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.before(TestFilter1.class), new BeforeFilter());
        testClassPlacementFilter(BeforeFilter.class, 1);
    }

    @Test
    void beforePlacement2() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.before(TestFilter2.class), new BeforeFilter());
        testClassPlacementFilter(BeforeFilter.class, 2);
    }

    @Test
    void beforePlacement3() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.before(TestFilter3.class), new BeforeFilter());
        testClassPlacementFilter(BeforeFilter.class, 3);
    }

    @Test
    void beforePlacementWhenMissing() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.before(PositionFilter.class), new BeforeFilter());
        testClassPlacementFilter(BeforeFilter.class, count);
    }

    @Test
    void afterPlacement1() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(TestFilter1.class), new AfterFilter());
        testClassPlacementFilter(AfterFilter.class, 2);
    }

    @Test
    void afterPlacement2() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(TestFilter2.class), new AfterFilter());
        testClassPlacementFilter(AfterFilter.class, 3);
    }

    @Test
    void afterPlacement3() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(TestFilter3.class), new AfterFilter());
        testClassPlacementFilter(AfterFilter.class, 4);
    }

    @Test
    void afterPlacementWhenMissing() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(PositionFilter.class), new AfterFilter());
        testClassPlacementFilter(AfterFilter.class, count);
    }

    public static class TestFilter1 implements Filter {

        @Override
        public void init(FilterConfig filterConfig) {
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        }
    }

    public static class TestFilter2 extends TestFilter1 {
    }

    public static class TestFilter3 extends TestFilter1 {
    }

    public static class PositionFilter extends TestFilter1 {
    }

    public static class AfterFilter extends TestFilter1 {
    }

    public static class BeforeFilter extends TestFilter1 {
    }
}