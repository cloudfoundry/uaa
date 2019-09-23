package org.cloudfoundry.identity.uaa.mfa;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class MfaProviderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testSerialize() {

        MfaProvider<GoogleMfaProviderConfig> provider = createValidGoogleMfaProvider();
        provider.setCreated(new Date());
        provider.setLastModified(new Date());
        String string = JsonUtils.writeValueAsString(provider);
        JsonNode output = JsonUtils.readTree(JsonUtils.writeValueAsString(provider));
        assertEquals(output.get("type").textValue(), MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR.toValue());
        JsonNode config = output.get("config");
        assertEquals(config.get("issuer").textValue(), "current-zone");
        assertEquals(config.get("providerDescription").textValue(), "config description");
    }

    @Test
    public void testDeserialize() {
        String json = "{\n" +
                "  \"type\" : \"google-authenticator\",\n" +
                "  \"config\" : {\n" +
                "    \"providerDescription\" : \"ddd\",\n" +
                "    \"issuer\": \"issuer\",\n" +
                "    \"algorithm\": \"SHA256\",\n" +
                "    \"digits\": 8, \n" +
                "    \"duration\": 32 \n" +
                "  },\n" +
                "  \"name\" : \"UAA Provider\",  \n" +
                "  \"active\" : true\n" +
                "}";

        MfaProvider<GoogleMfaProviderConfig> provider = JsonUtils.readValue(json, MfaProvider.class);

        assertEquals(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR, provider.getType());
        assertEquals("UAA Provider", provider.getName());
        GoogleMfaProviderConfig config = provider.getConfig();
        assertEquals("issuer", config.getIssuer());
        assertEquals("ddd", config.getProviderDescription());
    }


    @Test
    public void testDeserializeInvalidType() {
        String json = "{\n" +
                "  \"type\" : \"invalid-type\",\n" +
                "  \"config\" : {\n" +
                "    \"providerDescription\" : \"ddd\",\n" +
                "    \"issuer\": \"issuer\",\n" +
                "    \"algorithm\": \"SHA256\",\n" +
                "    \"digits\": 8, \n" +
                "    \"duration\": 32 \n" +
                "  },\n" +
                "  \"name\" : \"UAA Provider\" \n" +
                "}";

        MfaProvider<GoogleMfaProviderConfig> provider = JsonUtils.readValue(json, MfaProvider.class);

        assertNull(provider.getType());
        assertEquals("UAA Provider", provider.getName());
        assertNull(provider.getConfig());
    }

    @Test
    public void validateProviderActiveSetDefaultToTrue() {
        MfaProvider provider = createValidGoogleMfaProvider();
    }

    private MfaProvider createValidGoogleMfaProvider() {
        MfaProvider<GoogleMfaProviderConfig> res = new MfaProvider();
        res.setName(new RandomValueStringGenerator(5).generate())
                .setConfig(createValidGoogleMfaConfig())
                .setIdentityZoneId(IdentityZone.getUaaZoneId())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        return res;
    }

    private GoogleMfaProviderConfig createValidGoogleMfaConfig() {
        return (GoogleMfaProviderConfig) new GoogleMfaProviderConfig()
                .setProviderDescription("config description")
                .setIssuer("current-zone");
    }
}