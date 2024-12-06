package org.cloudfoundry.identity.uaa.provider.saml;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.config.YamlMapFactoryBean;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SamlConfigurationTest {

    @BeforeEach
    void setUp() {
        var mockAppCtx = mock(ConfigurableWebApplicationContext.class, Mockito.RETURNS_DEEP_STUBS);
        when(
                mockAppCtx.getEnvironment()
                        .getPropertySources()
                        .get("servletConfigYaml")
                        .getProperty("login")
        )
                .thenReturn(Map.of("saml", Map.of("providers", Map.of("idp.1", Map.of("idpMetadata", "<xml/>")))));
    }

    @Test
    void bindFromEnvironment() {
        var config = new ByteArrayResource("""
                login:
                  saml:
                    providers:
                      idp.one:
                        idpMetadata: "<xml />"
                    entityIDAlias: foo
                """.getBytes(StandardCharsets.UTF_8));

        // Build property source
        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResources(config);
        NestedMapPropertySource properties = new NestedMapPropertySource("servletConfigYaml", factory.getObject());

        // Set it in environment
        var env = new StandardEnvironment();
        env.getPropertySources().addFirst(properties);

        // Bootstrap the object
        var props = new SamlConfigProps();
        props.setEnvironment(env);

        // Call the Boot binding logic (more-or-less)
        Binder.get(env).bind("login.saml", Bindable.ofInstance(props)).get();

        // Assert
        assertThat(props).isNotNull()
                .hasFieldOrPropertyWithValue("entityIDAlias", "foo")
                .extracting("environmentProviders", InstanceOfAssertFactories.map(String.class, Map.class))
                .extractingByKey("idp.one")
                .extracting("idpMetadata")
                .isEqualTo("<xml />");
    }

    @Test
    void bootstrapMetaDataProviders() {
        SamlConfiguration samlConfiguration = new SamlConfiguration();
        assertThatNoException().isThrownBy(() ->
                samlConfiguration.bootstrapMetaDataProviders(mock(SamlConfigProps.class), mock(SamlIdentityProviderConfigurator.class)));
    }
}
