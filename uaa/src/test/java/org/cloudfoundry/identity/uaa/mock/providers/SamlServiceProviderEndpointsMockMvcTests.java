package org.cloudfoundry.identity.uaa.mock.providers;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class SamlServiceProviderEndpointsMockMvcTests extends InjectedMockContextTest {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String accessToken;

    @Before
    public void setUp() throws Exception {
        accessToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null, "");
    }

    @Test
    public void createServiceProvider() throws Exception {
        SamlServiceProvider serviceProvider = getSamlServiceProvider();

        getMockMvc().perform(post("/saml/service-providers")
            .header("Authorization", "bearer" + accessToken)
            .header("Content-Type", "application/json")
            .content(JsonUtils.writeValueAsString(serviceProvider)))
          .andExpect(status().isCreated());
    }

    @Test
    public void createServiceProvider_invalidEntityId() throws Exception {
        SamlServiceProvider serviceProvider = getSamlServiceProvider();
        serviceProvider.setEntityId("cloudfoundry-saml-login-invalid");

        getMockMvc().perform(post("/saml/service-providers")
          .header("Authorization", "bearer" + accessToken)
          .header("Content-Type", "application/json")
          .content(JsonUtils.writeValueAsString(serviceProvider)))
          .andExpect(status().isBadRequest());
    }

    private SamlServiceProvider getSamlServiceProvider() {
        String spName = generator.generate();
        SamlServiceProvider serviceProvider = new SamlServiceProvider();
        serviceProvider.setName(spName);
        serviceProvider.setActive(true);

        SamlServiceProviderDefinition config = new SamlServiceProviderDefinition();
        config.setMetaDataLocation(SamlTestUtils.SAML_SP_METADATA);
        config.setMetadataTrustCheck(true);
        serviceProvider.setConfig(config);
        return serviceProvider;
    }
}
