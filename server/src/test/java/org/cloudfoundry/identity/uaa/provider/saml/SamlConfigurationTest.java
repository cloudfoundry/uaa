package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.cloudfoundry.identity.uaa.oauth.beans.ApplicationContextProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SamlConfigurationTest {

    ApplicationContextProvider applicationContextProvider;
    SamlIdentityProviderConfigurator samlIdentityProviderConfigurator;
    SamlConfigProps configProps;
    ConfigurableWebApplicationContext webApplicationContext;
    ConfigurableEnvironment environment;
    MutablePropertySources propertySources;
    PropertySource nestedMapPropertySource;

    @BeforeEach
    void setUp() {
        applicationContextProvider = new ApplicationContextProvider();
        samlIdentityProviderConfigurator = mock(SamlIdentityProviderConfigurator.class);
        webApplicationContext = mock(ConfigurableWebApplicationContext.class);
        environment = mock(ConfigurableEnvironment.class);
        configProps = new SamlConfigProps();
        propertySources = mock(MutablePropertySources.class);
        nestedMapPropertySource = mock(NestedMapPropertySource.class);
        applicationContextProvider.setApplicationContext(webApplicationContext);
        when(webApplicationContext.getEnvironment()).thenReturn(environment);
        when(environment.getPropertySources()).thenReturn(propertySources);
        when(propertySources.get("servletConfigYaml")).thenReturn(nestedMapPropertySource);
        when(nestedMapPropertySource.getProperty("login")).thenReturn(Map.of("saml", Map.of("providers", Map.of("idp.1", Map.of("idpMetadata", "<xml/>")))));
    }

    @Test
    void bootstrapMetaDataProviders() {
        SamlConfiguration samlConfiguration = new SamlConfiguration(applicationContextProvider);
        assertNotNull(samlConfiguration.bootstrapMetaDataProviders(configProps, samlIdentityProviderConfigurator));
    }

    @Test
    void bootstrapMetaDataProvidersNoApplicationContext() {
        SamlConfiguration samlConfiguration = new SamlConfiguration(null);
        assertNotNull(samlConfiguration.bootstrapMetaDataProviders(configProps, samlIdentityProviderConfigurator));
    }

    @Test
    void bootstrapMetaDataProvidersNoWebApplicationContext() {
        SamlConfiguration samlConfiguration = new SamlConfiguration(applicationContextProvider);
        configProps.setProviders(Map.of("login", Map.of()));
        applicationContextProvider.setApplicationContext(null);
        assertThrowsExactly(IllegalArgumentException.class, () -> samlConfiguration.bootstrapMetaDataProviders(configProps, samlIdentityProviderConfigurator));
    }

    @Test
    void bootstrapMetaDataProvidersInvalidProviders() {
        SamlConfiguration samlConfiguration = new SamlConfiguration(applicationContextProvider);
        configProps.setProviders(Map.of("login", Map.of()));
        when(nestedMapPropertySource.getProperty("login")).thenReturn(Map.of("saml", Map.of("providers", Map.of("idp.1", Map.of()))));
        assertThrowsExactly(IllegalArgumentException.class, () -> samlConfiguration.bootstrapMetaDataProviders(configProps, samlIdentityProviderConfigurator));
    }

    @Test
    void bootstrapMetaDataProvidersValidProviders() {
        SamlConfiguration samlConfiguration = new SamlConfiguration(applicationContextProvider);
        configProps.setProviders(Map.of("login", Map.of("saml", Map.of("providers", Map.of("idp.1", Map.of("idpMetadata", "<xml/>"))))));
        BootstrapSamlIdentityProviderData idpData = samlConfiguration.bootstrapMetaDataProviders(configProps, samlIdentityProviderConfigurator);
        assertNotNull(idpData);
        assertEquals(1, idpData.getProviders().size());
    }
}