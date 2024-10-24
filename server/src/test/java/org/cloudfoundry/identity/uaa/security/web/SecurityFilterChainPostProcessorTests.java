package org.cloudfoundry.identity.uaa.security.web;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SecurityFilterChainPostProcessorTests {

    private final SecurityFilterChainPostProcessor processor = new SecurityFilterChainPostProcessor();
    private SecurityFilterChain fc;
    private final Map<SecurityFilterChainPostProcessor.FilterPosition, Filter> additionalFilters = new HashMap<>();
    private int count;

    @Before
    public void setUp() {
        List<Filter> filters = new LinkedList<>();
        filters.add(new TestFilter1());
        filters.add(new TestFilter2());
        filters.add(new TestFilter3());
        fc = mock(SecurityFilterChain.class);
        when(fc.getFilters()).thenReturn(filters);
        count = filters.size() + 1;
    }

    @After
    public void tearDown() {

    }

    private void testPositionFilter(int pos) {
        int expectedPos = pos > count ? count : pos + 1;
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(pos), new PositionFilter());
        processor.setAdditionalFilters(additionalFilters);
        processor.postProcessAfterInitialization(fc, "");
        assertThat(fc.getFilters()).hasSize(count + 1);
        assertThat(fc.getFilters().get(expectedPos).getClass()).as(String.format("filter[%d] should be:%s", pos, PositionFilter.class.getSimpleName())).isEqualTo(PositionFilter.class);
    }

    @Test
    public void testPosition0Filter() {
        testPositionFilter(0);
    }

    @Test
    public void testPosition1Filter() {
        testPositionFilter(1);
    }

    @Test
    public void testPositionLastFilter() {
        testPositionFilter(Integer.MAX_VALUE);
    }

    private void testClassPlacementFilter(Class<?> clazz, int expectedPosition) {
        processor.setAdditionalFilters(additionalFilters);
        processor.postProcessAfterInitialization(fc, "");
        assertThat(fc.getFilters()).hasSize(count + 1);
        assertThat(clazz).as(String.format("filter[%s] should be at position:%d", clazz.getSimpleName(), expectedPosition)).isEqualTo(fc.getFilters().get(expectedPosition).getClass());
    }

    @Test
    public void testBeforePlacement1() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.before(TestFilter1.class), new BeforeFilter());
        testClassPlacementFilter(BeforeFilter.class, 1);
    }

    @Test
    public void testBeforePlacement2() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.before(TestFilter2.class), new BeforeFilter());
        testClassPlacementFilter(BeforeFilter.class, 2);
    }

    @Test
    public void testBeforePlacement3() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.before(TestFilter3.class), new BeforeFilter());
        testClassPlacementFilter(BeforeFilter.class, 3);
    }

    @Test
    public void testBeforePlacementWhenMissing() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.before(PositionFilter.class), new BeforeFilter());
        testClassPlacementFilter(BeforeFilter.class, count);
    }

    @Test
    public void testAfterPlacement1() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(TestFilter1.class), new AfterFilter());
        testClassPlacementFilter(AfterFilter.class, 2);
    }

    @Test
    public void testAfterPlacement2() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(TestFilter2.class), new AfterFilter());
        testClassPlacementFilter(AfterFilter.class, 3);
    }

    @Test
    public void testAfterPlacement3() {
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(TestFilter3.class), new AfterFilter());
        testClassPlacementFilter(AfterFilter.class, 4);
    }

    @Test
    public void testAfterPlacementWhenMissing() {
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