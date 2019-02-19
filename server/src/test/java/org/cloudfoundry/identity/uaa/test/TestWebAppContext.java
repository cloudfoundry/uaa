package org.cloudfoundry.identity.uaa.test;


import io.honeycomb.libhoney.EventFactory;
import io.honeycomb.libhoney.HoneyClient;
import io.honeycomb.libhoney.LibHoney;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.cloudfoundry.identity.uaa.impl.config.YamlMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.*;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.yaml.snakeyaml.Yaml;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;

@Configuration
@PropertySource(value = {
  "file:../uaa/src/test/resources/test/bootstrap/all-properties-set.yml"
}, factory = NestedMapPropertySourceFactory.class)
@ImportResource(locations = {
  "file:../uaa/src/main/webapp/WEB-INF/spring-servlet.xml"
})
public class TestWebAppContext implements InitializingBean {
    @Autowired
    DataSource dataSource;

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

        EventFactory.Builder builder = honeyClient.buildEventFactory()
                .addField("junit", "5")
                .addField("testId", testId)
                .addField("cpuCores", Runtime.getRuntime().availableProcessors())
                .addField("hostname", hostName);
        for (Map.Entry entry : System.getProperties().entrySet()) {
            builder.addField(entry.getKey().toString(), entry.getValue());
        }

        builder.addField("DB", System.getenv().get("DB"));
        builder.addField("SPRING_PROFILE", System.getenv().get("SPRING_PROFILE"));
        builder.addField("JAVA_HOME", System.getenv().get("JAVA_HOME"));

        return builder.build();
    }

    @Bean
    public HoneycombAuditEventTestListener honeycombAuditEventTestListenerAuthenticationFailureLockedEvent(ConfigurableApplicationContext configurableApplicationContext, EventFactory honeycombEventFactory) {
        HoneycombAuditEventTestListener<AuthenticationFailureLockedEvent> listener =
                HoneycombAuditEventTestListener.forEventClass(AuthenticationFailureLockedEvent.class);
        listener.setHoneycombEventFactory(honeycombEventFactory);
        configurableApplicationContext.addApplicationListener(listener);
        return listener;
    }

    @Bean
    public HoneycombAuditEventTestListener honeycombAuditEventTestListenerIdentityProviderAuthenticationFailureEvent(ConfigurableApplicationContext configurableApplicationContext,EventFactory honeycombEventFactory) {
        HoneycombAuditEventTestListener<IdentityProviderAuthenticationFailureEvent> listener =
                HoneycombAuditEventTestListener.forEventClass(IdentityProviderAuthenticationFailureEvent.class);
        listener.setHoneycombEventFactory(honeycombEventFactory);
        configurableApplicationContext.addApplicationListener(listener);
        return listener;
    }

    @Bean
    public HoneycombAuditEventTestListener honeycombAuditEventTestListenerMfaAuthenticationFailureEvent(ConfigurableApplicationContext configurableApplicationContext, EventFactory honeycombEventFactory) {
        HoneycombAuditEventTestListener<MfaAuthenticationFailureEvent> listener =
                HoneycombAuditEventTestListener.forEventClass(MfaAuthenticationFailureEvent.class);
        listener.setHoneycombEventFactory(honeycombEventFactory);
        configurableApplicationContext.addApplicationListener(listener);
        return listener;
    }

    @Autowired
    private EventFactory honeycombEventFactory;

    @Override
    public void afterPropertiesSet() {
        HoneycombJdbcInterceptor.honeyCombEventFactory = honeycombEventFactory;
        dataSource.setJdbcInterceptors("org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptor");
    }
}

class NestedMapPropertySourceFactory implements PropertySourceFactory {
    @Override
    public org.springframework.core.env.PropertySource<?> createPropertySource(String name, EncodedResource resource) {
        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResolutionMethod(YamlProcessor.ResolutionMethod.OVERRIDE_AND_IGNORE);
        factory.setResources(new Resource[]{resource.getResource()});

        Map<String, Object> yamlMap = factory.getObject();
        String yamlStr = (new Yaml()).dump(yamlMap);
        yamlMap.put("environmentYamlKey", yamlStr);

        return new NestedMapPropertySource("servletConfigYaml", yamlMap);
    }
}