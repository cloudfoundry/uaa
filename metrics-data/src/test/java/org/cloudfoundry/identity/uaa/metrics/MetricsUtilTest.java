package org.cloudfoundry.identity.uaa.metrics;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.Assertions.within;

class MetricsUtilTest {

    private static final double DELTA = 1e-15;

    @Test
    void addToAverage() {
        double average = 1.0;
        double avergeCount = 1.0;

        double newAverage = MetricsUtil.addToAverage(avergeCount, average, 1.0, 1.0);
        assertThat(newAverage).isCloseTo(1.0, within(DELTA));

        newAverage = MetricsUtil.addToAverage(avergeCount, average, 20.0, 20.0);
        assertThat(newAverage).isCloseTo(1.0, within(DELTA));

        newAverage = MetricsUtil.addToAverage(avergeCount, average, 0, 0);
        assertThat(newAverage).isCloseTo(1.0, within(DELTA));
    }

    @Test
    void addAverages() {
        double average = 1.0;
        double avergeCount = 1.0;

        double newAverage = MetricsUtil.addAverages(avergeCount, average, 5.0, 1.0);
        assertThat(newAverage).isCloseTo(1.0, within(DELTA));

        newAverage = MetricsUtil.addAverages(avergeCount, average, 20.0, 1.0);
        assertThat(newAverage).isCloseTo(1.0, within(DELTA));

        newAverage = MetricsUtil.addAverages(avergeCount, average, 0, 0);
        assertThat(newAverage).isCloseTo(1.0, within(DELTA));
    }

    @Test
    void mutableLong() {
        MetricsUtil.MutableLong mlong = new MetricsUtil.MutableLong(1);
        assertThat(mlong.get()).isEqualTo(1L);
        mlong.add(1L);
        assertThat(mlong.get()).isEqualTo(2L);
        mlong.set(1L);
        assertThat(mlong.get()).isEqualTo(1L);
        assertThat(mlong.toString()).isEqualTo("1");
    }

    @Test
    void mutableDouble() {
        MetricsUtil.MutableDouble mlong = new MetricsUtil.MutableDouble(1.0);
        assertThat(mlong.get()).isEqualTo(1.0d);
        mlong.add(1.5d);
        assertThat(mlong.get()).isEqualTo(2.5d);
        mlong.set(1.0d);
        assertThat(mlong.get()).isEqualTo(1.0d);
        assertThat(mlong.toString()).isEqualTo("1.0");
    }

    @Test
    void cannotInstantiate() {
        Constructor<?>[] constructors = MetricsUtil.class.getDeclaredConstructors();
        for (Constructor c : constructors) {
            c.setAccessible(true);
            try {
                c.newInstance();
                fail("MetricsUtil should not be instantiable");
            } catch (InvocationTargetException e) {
                assertThat(e).isInstanceOf(InvocationTargetException.class);
                assertThat(e.getCause().getMessage()).isEqualTo("Utility class");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}