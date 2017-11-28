package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.impl.config.YamlMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class MfaProviderBootstrapTest extends JdbcTestBase {

    private MfaProviderBootstrap bootstrap;
    private MfaProviderProvisioning provisioning;
    private Map<String, Map<String, Object>> sampleData;

    private String sampleMfaYaml = "mfa-providers:\n" +
            "  provider-name1:\n" +
            "    type : google-authenticator\n" +
            "    config :\n" +
            "      providerDescription : mfa provider description\n" +
            "      digits: 6\n" +
            "      duration : 30\n" +
            "      algorithm : \"SHA256\"\n" +
            "      issuer: \"Issuer\"\n" +
            "  provider-name2:\n" +
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
    @Override
    public void setUp() throws Exception {
        super.setUp();
        provisioning = spy(new JdbcMfaProviderProvisioning(jdbcTemplate, mfaProvider -> {}));
        bootstrap = new MfaProviderBootstrap(provisioning);
        sampleData = parseMfaYaml(sampleMfaYaml);
        expectedGoogleProviders = new ArrayList<>();

        GoogleMfaProviderConfig googleMfaProviderConfig = new GoogleMfaProviderConfig();
        googleMfaProviderConfig.setIssuer("Issuer");
        googleMfaProviderConfig.setProviderDescription("mfa provider description");

        MfaProvider<GoogleMfaProviderConfig> providerOne = new MfaProvider<>();
        providerOne.setName("provider-name1");
        providerOne.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        providerOne.setIdentityZoneId("uaa");
        providerOne.setConfig(googleMfaProviderConfig);

        MfaProvider<GoogleMfaProviderConfig> providerTwo = new MfaProvider<>();
        providerTwo.setName("provider-name2");
        providerTwo.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        providerTwo.setIdentityZoneId("uaa");
        providerTwo.setConfig(googleMfaProviderConfig);

        unbootstrappedProvider = new MfaProvider<>();
        unbootstrappedProvider.setId("mfa-id");
        unbootstrappedProvider.setName("provider-name-not-bootstrapped");
        unbootstrappedProvider.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        unbootstrappedProvider.setIdentityZoneId("uaa");
        unbootstrappedProvider.setConfig(googleMfaProviderConfig);

        expectedGoogleProviders.add(providerOne);
        expectedGoogleProviders.add(providerTwo);
    }

    @Test
    public void testParseMfaProviders() throws Exception {
        bootstrap.setMfaProviders(sampleData);
        assertThat(bootstrap.getMfaProviders(),  containsInAnyOrder(expectedGoogleProviders.toArray()));
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
        provisioning.create(expectedGoogleProviders.get(0), "uaa");
        reset(provisioning);
        bootstrap.setMfaProviders(parseMfaYaml(sampleMfaYaml.replace("mfa provider description", "new description")));
        bootstrap.afterPropertiesSet();
        ArgumentCaptor<MfaProvider> captor = ArgumentCaptor.forClass(MfaProvider.class);
        verify(provisioning).update(captor.capture(), eq("uaa"));
        verify(provisioning).create(eq(expectedGoogleProviders.get(1)), eq("uaa"));
        assertEquals("new description", ((GoogleMfaProviderConfig)captor.getValue().getConfig()).getProviderDescription());
        assertEquals("new description", ((GoogleMfaProviderConfig)provisioning.retrieveByName(expectedGoogleProviders.get(0).getName(), "uaa").getConfig()).getProviderDescription());
    }

    public Map<String, Map<String, Object>> parseMfaYaml(String sampleYaml) {
        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResolutionMethod(YamlProcessor.ResolutionMethod.OVERRIDE_AND_IGNORE);
        List<Resource> resources = new ArrayList<>();
        ByteArrayResource resource = new ByteArrayResource(sampleYaml.getBytes());
        resources.add(resource);
        factory.setResources(resources.toArray(new Resource[resources.size()]));
        Map<String, Object> tmpdata = factory.getObject();
        Map<String, Map<String, Object>> dataList = new HashMap<>();
        for (Map.Entry<String, Map<String, Object>> entry : ((Map<String, Map<String, Object>>)tmpdata.get("mfa-providers")).entrySet()) {
            dataList.put(entry.getKey(), entry.getValue());
        }
        return dataList;
    }


}