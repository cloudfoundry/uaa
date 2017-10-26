package org.cloudfoundry.identity.uaa.mfa_provider;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import javax.xml.bind.ValidationException;

import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

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
        assertEquals(config.get("algorithm").textValue(), GoogleMfaProviderConfig.Algorithm.SHA256.toString());
        assertEquals(config.get("digits").intValue(), 42);
        assertEquals(config.get("issuer").textValue(), "current-zone");
        assertEquals(config.get("duration").intValue(), 13);
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
        assertEquals(true, provider.isActive());
        GoogleMfaProviderConfig config = provider.getConfig();
        assertEquals(GoogleMfaProviderConfig.Algorithm.SHA256, config.getAlgorithm());
        assertEquals(8, config.getDigits());
        assertEquals(32, config.getDuration());
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
                "  \"name\" : \"UAA Provider\",  \n" +
                "  \"active\" : true\n" +
                "}";

        MfaProvider<GoogleMfaProviderConfig> provider = JsonUtils.readValue(json, MfaProvider.class);

        assertEquals(null, provider.getType());
        assertEquals("UAA Provider", provider.getName());
        assertEquals(true, provider.isActive());
        assertNull(provider.getConfig());
    }

    @Test
    public void validateProviderActiveSetDefaultToTrue() {
        MfaProvider provider = createValidGoogleMfaProvider();
        assertTrue(provider.isActive());
    }

    private MfaProvider createValidGoogleMfaProvider() {
        MfaProvider<GoogleMfaProviderConfig> res = new MfaProvider();
        res.setName(new RandomValueStringGenerator(5).generate())
                .setConfig(createValidGoogleMfaConfig())
                .setIdentityZoneId(IdentityZone.getUaa().getId())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        return res;
    }

    private GoogleMfaProviderConfig createValidGoogleMfaConfig() {
        return new GoogleMfaProviderConfig()
                .setProviderDescription("config description")
                .setIssuer("current-zone")
                .setAlgorithm(GoogleMfaProviderConfig.Algorithm.SHA256)
                .setDigits(42)
                .setDuration(13);
    }
}