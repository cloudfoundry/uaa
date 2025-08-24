package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.impl.config.EnvironmentMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.EnvironmentPropertiesFactoryBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.env.Environment;
import org.springframework.jmx.export.MBeanExporter;
import org.springframework.jmx.export.annotation.AnnotationMBeanExporter;
import org.springframework.jmx.export.assembler.MethodNameBasedMBeanInfoAssembler;
import org.springframework.jmx.support.MBeanServerFactoryBean;
import org.springframework.jmx.support.RegistrationPolicy;

import javax.management.MBeanServer;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

@Configuration
public class EnvXmlBeanConfiguration {

    @Bean
    // <bean id="applicationProperties" class="org.springframework.beans.factory.config.PropertiesFactoryBean">
    PropertiesFactoryBean applicationProperties(Environment environment) throws IOException {
        PropertiesFactoryBean bean = new PropertiesFactoryBean();
        EnvironmentPropertiesFactoryBean envFactoryBean = new EnvironmentPropertiesFactoryBean();
        envFactoryBean.setEnvironment(environment);
        bean.setPropertiesArray(envFactoryBean.getObject());
        bean.afterPropertiesSet();
        return bean;
    }

    @Bean
    // <context:property-placeholder properties-ref="applicationProperties"/>
    PropertySourcesPlaceholderConfigurer propertyPlaceHolder(
            @Qualifier("applicationProperties") PropertiesFactoryBean applicationProperties
    ) throws IOException {
        PropertySourcesPlaceholderConfigurer bean = new PropertySourcesPlaceholderConfigurer();
        bean.setIgnoreUnresolvablePlaceholders(false);
        bean.setProperties(applicationProperties.getObject());
        return bean;
    }

    @Bean(name = "mbeanServer")
    @Role(2) //ROLE_INFRASTRUCTURE
    // <context:mbean-server id="mbeanServer"/>
    MBeanServer mbeanServer() {
        MBeanServerFactoryBean bean = new MBeanServerFactoryBean();
        bean.setLocateExistingServerIfPossible(true);
        bean.afterPropertiesSet();
        return bean.getObject();
    }

    @Bean
    // <context:mbean-export server="mbeanServer" default-domain="spring.application" registration="replaceExisting"/>
    AnnotationMBeanExporter mbeanExporter(@Qualifier("mbeanServer") MBeanServer mbeanServer) {
        AnnotationMBeanExporter bean = new AnnotationMBeanExporter();
        bean.setDefaultDomain("spring.application");
        bean.setRegistrationPolicy(RegistrationPolicy.REPLACE_EXISTING);
        bean.setServer(mbeanServer);
        bean.afterPropertiesSet();
        return bean;
    }

    @Bean
    EnvironmentMapFactoryBean config() {
        return new EnvironmentMapFactoryBean();
    }

    @Bean
    @Role(2) //ROLE_INFRASTRUCTURE
    // <bean class="org.springframework.jmx.export.MBeanExporter">
    MBeanExporter mbeanExporter2(
            @Qualifier("mbeanServer") MBeanServer mbeanServer,
            @Qualifier("config") EnvironmentMapFactoryBean config
    ) {
        MBeanExporter bean = new MBeanExporter();
        bean.setRegistrationPolicy(RegistrationPolicy.REPLACE_EXISTING);
        bean.setServer(mbeanServer);
        Map<String, Object> beans = new LinkedHashMap<>();
        beans.put("spring.application:type=Config,name=uaa", config);
        bean.setBeans(beans);
        MethodNameBasedMBeanInfoAssembler assembler = new MethodNameBasedMBeanInfoAssembler();
        Properties mappings = new Properties();
        mappings.put("spring.application:type=Config,name=uaa", "getObject");
        bean.setAssembler(assembler);
        bean.afterPropertiesSet();
        return bean;
    }
}
