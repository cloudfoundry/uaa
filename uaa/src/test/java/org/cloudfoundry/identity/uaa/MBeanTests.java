package org.cloudfoundry.identity.uaa;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jmx.export.MBeanExporter;
import org.springframework.jmx.export.annotation.AnnotationMBeanExporter;

import javax.management.MBeanFeatureInfo;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

@DefaultTestContext
class MBeanTests {

    @Autowired
    private MBeanServer mBeanServer;

    @Autowired
    AnnotationMBeanExporter mbeanExporter;

    @Autowired
    MBeanExporter mbeanExporter2;

    @Test
    void beansAreSet() {
        assertThat(mBeanServer).isNotNull();
        assertThat(mbeanExporter).isNotNull();
        assertThat(mbeanExporter2).isNotNull();
    }

    @Test
    void testDataSourceExporter() throws Exception {
        ObjectName objectName = new ObjectName("spring.application:type=DataSource,name=dataSource");

        assertThat(mBeanServer.isRegistered(objectName)).isTrue();

        var mbeanNames = Arrays.stream(mBeanServer.getMBeanInfo(objectName).getAttributes())
                .map(MBeanFeatureInfo::getName);
        assertThat(mbeanNames).containsExactlyInAnyOrder("MaxActive", "MaxIdle", "NumActive", "NumIdle");
    }
}
