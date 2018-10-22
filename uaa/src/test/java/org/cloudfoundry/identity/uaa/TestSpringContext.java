package org.cloudfoundry.identity.uaa;

import io.honeycomb.libhoney.EventFactory;
import io.honeycomb.libhoney.HoneyClient;
import io.honeycomb.libhoney.LibHoney;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListener;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;

import java.net.InetAddress;
import java.net.UnknownHostException;

@Configuration
@ImportResource(locations = {
        "file:./src/main/webapp/WEB-INF/spring-servlet.xml"
})
@PropertySource(value = "classpath:integration_test_properties.yml", factory = NestedMapPropertySourceFactory.class)
public class TestSpringContext {
    @Bean
    public static PropertySourcesPlaceholderConfigurer properties() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Bean
    public EventFactory honeycombEventFactory(@Value("#{T(System).getenv('HONEYCOMB_KEY')}") String honeycombKey,
                                              @Value("#{T(System).getenv('HONEYCOMB_DATASET')}") String dataset,
                                              @Value("${testId:-1}") String testId) {
        HoneyClient honeyClient = LibHoney.create(
                LibHoney.options()
                        .setWriteKey(honeycombKey)
                        .setDataset(dataset)
                        .build()
        );

        if (honeycombKey == null || dataset == null) {
            return honeyClient.buildEventFactory().build();
        }

        String hostName = "";
        try {
            hostName = InetAddress.getLocalHost().getHostName();

        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        return honeyClient.buildEventFactory()
                .addField("testId", testId)
                .addField("cpuCores", Runtime.getRuntime().availableProcessors())
                .addField("hostname", hostName)
                .build();
    }

    @Bean
    public HoneycombAuditEventTestListener honeycombAuditEventTestListener(EventFactory honeycombEventFactory) {
        HoneycombAuditEventTestListener<AuthenticationFailureLockedEvent> listener =
                HoneycombAuditEventTestListener.forEventClass(AuthenticationFailureLockedEvent.class);
        listener.setHoneycombEventFactory(honeycombEventFactory);
        return listener;
    }
}
