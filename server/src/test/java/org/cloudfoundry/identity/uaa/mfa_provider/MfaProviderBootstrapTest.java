package org.cloudfoundry.identity.uaa.mfa_provider;

import org.cloudfoundry.identity.uaa.impl.config.YamlMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.dao.EmptyResultDataAccessException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class MfaProviderBootstrapTest {

    private MfaProviderBootstrap bootstrap;
    private MfaProviderProvisioning provisioning;
    private List<Map<String, Object>> sampleData;

    private String sampleMfaYaml = "mfa-providers:\n" +
            "  - name : provider-name1\n" +
            "    type : google-authenticator\n" +
            "    config :\n" +
            "      providerDescription : mfa provider description\n" +
            "      digits: 6\n" +
            "      duration : 30\n" +
            "      algorithm : \"SHA256\"\n" +
            "      issuer: \"Issuer\"\n" +
            "  - name : provider-name2\n" +
            "    type : google-authenticator\n" +
            "    config :\n" +
            "      providerDescription : mfa provider description\n" +
            "      digits: 6\n" +
            "      duration : 30\n" +
            "      algorithm : \"SHA256\"\n" +
            "      issuer: \"Issuer\"\n";

    private List<MfaProvider<GoogleMfaProviderConfig>> expectedGoogleProviders;
    private MfaProvider<GoogleMfaProviderConfig> unbootstrappedProvider;

    @Before
    public void setUp() throws Exception {
        provisioning = mock(MfaProviderProvisioning.class);
        bootstrap = new MfaProviderBootstrap(provisioning);
        sampleData = parseMfaYaml(sampleMfaYaml);
        expectedGoogleProviders = new ArrayList<>();

        GoogleMfaProviderConfig googleMfaProviderConfig = new GoogleMfaProviderConfig();
        googleMfaProviderConfig.setIssuer("Issuer");
        googleMfaProviderConfig.setProviderDescription("mfa provider description");
        googleMfaProviderConfig.setDigits(6);
        googleMfaProviderConfig.setAlgorithm(GoogleMfaProviderConfig.Algorithm.SHA256);
        googleMfaProviderConfig.setDuration(30);

        MfaProvider<GoogleMfaProviderConfig> providerOdin = new MfaProvider<>();
        providerOdin.setName("provider-name1");
        providerOdin.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        providerOdin.setIdentityZoneId("uaa");
        providerOdin.setConfig(googleMfaProviderConfig);

        MfaProvider<GoogleMfaProviderConfig> providerDva = new MfaProvider<>();
        providerDva.setName("provider-name2");
        providerDva.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        providerDva.setIdentityZoneId("uaa");
        providerDva.setConfig(googleMfaProviderConfig);

        unbootstrappedProvider = new MfaProvider<>();
        unbootstrappedProvider.setId("mfa-id");
        unbootstrappedProvider.setName("provider-name-not-bootstrapped");
        unbootstrappedProvider.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        unbootstrappedProvider.setIdentityZoneId("uaa");
        unbootstrappedProvider.setConfig(googleMfaProviderConfig);

        expectedGoogleProviders.add(providerOdin);
        expectedGoogleProviders.add(providerDva);
    }

    @Test
    public void testParseMfaProviders() throws Exception {
        bootstrap.setMfaProviders(sampleData);
        assertEquals(bootstrap.getMfaProviders(),  expectedGoogleProviders);
    }

    @Test
    public void testAfterPropertiesSet() throws Exception {
        bootstrap.setMfaProviders(sampleData);
        bootstrap.afterPropertiesSet();
        verify(provisioning).create(expectedGoogleProviders.get(0), "uaa");
        verify(provisioning).create(expectedGoogleProviders.get(1), "uaa");
    }

    @Test
    public void testBootstrapWithSomeExistingProviders() throws Exception {
        bootstrap.setMfaProviders(sampleData);
        when(provisioning.retrieveByName("provider-name1", "uaa")).thenReturn(expectedGoogleProviders.get(0));
        when(provisioning.retrieveByName("provider-name2", "uaa")).thenThrow(new EmptyResultDataAccessException(1));

        bootstrap.afterPropertiesSet();
        verify(provisioning).update(any(), eq("uaa"));
        verify(provisioning).create(expectedGoogleProviders.get(1), "uaa");
    }

    public List<Map<String, Object>> parseMfaYaml(String sampleYaml) {
        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResolutionMethod(YamlProcessor.ResolutionMethod.OVERRIDE_AND_IGNORE);
        List<Resource> resources = new ArrayList<>();
        ByteArrayResource resource = new ByteArrayResource(sampleYaml.getBytes());
        resources.add(resource);
        factory.setResources(resources.toArray(new Resource[resources.size()]));
        Map<String, Object> tmpdata = factory.getObject();
        List<Map<String, Object>> dataList = new ArrayList<>();
        for (Map<String, Object> entry : (List<Map<String, Object>>)tmpdata.get("mfa-providers")) {
            dataList.add(entry);
        }
        return Collections.unmodifiableList(dataList);
    }


}