package org.cloudfoundry.identity.uaa.mock.token;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.any;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsMapContaining.hasKey;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class TokenKeyEndpointMockMvcTests {

    private static final String signKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIIEpQIBAAKCAQEA5JgjYNjLOeWC1Xf/NFcremS9peiQd3esa64KZ0BJue74bEtp\n" +
      "N8CLmbeTD9NHvKzCg833cF81gkrkP/pkra7WZF+zNlHBDnO68D/tBkEAzPJYlFLL\n" +
      "bMgvgL90fLbev4tlEUD59e0QGJQjIrcieOJSoOBSc8SqhVN61pdzT3rTUx+pq+QP\n" +
      "XpBor+HUOzRPpVfcTkwfxjVUTzJkSDI4pWS59+1NRVPhQBCPpG7j68VM60gJl+Bn\n" +
      "NzSI3gbvnh+UYrFvKA/fRkerAsz/Zy6LbGDAFYEQjpphGyQmtsqsOndL9zBvfQCp\n" +
      "5oT4hukBc3yIR6GVXDi0UURVjKtlYMMD4O+fqwIDAQABAoIBAQCi8VtOflomc9XV\n" +
      "ygpMydIBFWwlpefMcK6jttRNkwK6mX/U2dAvYH1h3fvi7OyWreKdRySYohUnQbD/\n" +
      "dcFsGFNUCu9Yyd++KHpZJIgUzCMA88J2P6onaW6K7G3hNA0FJhytts42IXw2uOlu\n" +
      "pnHZDyJs8Fl1kfsmvEG0UxJr1hZqia9QbyylQcsuBGz82EIrGYXSkHJgzlklcMSH\n" +
      "WSn5JfJ8W8gpD0NwMnsdK3udXy8HNp6iWTvkJhot8qV86VO/V9vttj+/4eNioMSR\n" +
      "eSVsO/1vGk10glX2bxwHPUy3wrAwgXbtOUSpkG9qDJ7qXHKkR7Pucjbq30AIu7VK\n" +
      "BsyRBv2RAoGBAPg0exT7ZmQFxOyHA260wEvdPh6mGRP5ZxwYJ9h35kiyuZPoMHRL\n" +
      "9IPOSMJdHXvxnOhE0Y3/oFlchvBbrnwo1JHo4B61lGSgvxu84JaDNdMETpKS7hS0\n" +
      "f1T1IQJsuRKZXllTd8pemKkpU4GlbQlpaAWZlNqjn1bs66ecu+o4KkWjAoGBAOvF\n" +
      "/bu4g2lk5Y6CYEO1xsfZjVVaLEDXKAVWBjyLd084nlA/IJsrb7xVg0KR3jFKTb7k\n" +
      "ZRNaTOeoJASLcqcgFNHGIxGhdzkj8rlDzrSNGGT1fdm97NQrkCmdtNfCSwR7qU6m\n" +
      "9fFoYoq+nmvCUJfK8x1QeqTW2+ToApvL4rhxv45ZAoGBALUl4Fq87Mq9Zy7VjwzC\n" +
      "QMJds5O81/q7AKUBgDs9rsWKI2Uuhgaq1MdJy9KHERi/iyv95g9D7OyrWhScZSla\n" +
      "x2HCW6guECKtKy18WVGga60ZrJrPP5G+9lu0GCZj4WMQqkp5X6lEBxkW/0pUyNKg\n" +
      "qnnD0F8OIiHYAlmvS3qzCS8PAoGAdntqxPk2YLJpgbIW+i/REwFKuwezkWoOHJBc\n" +
      "VfSoIlGLjTwMAK5VWkmGyt9Oz2pNo45XFOCeIRQn9Xi2RzIiBEETwnpn1XkxMtTW\n" +
      "fXkiNyn+8ns1FnJF4gP0qzBiToBuVq4kjgos6xhbuD9QDNfaUHLvDwNCQcgt92kA\n" +
      "KDxRTRECgYEA6ClxlKmBV7Y++PnlJjsXFGUC1Pk3HX/YBxXWsJgdyPvyxNEPmYc9\n" +
      "YCencbzky95AQIC+isTAQOvk59WeNjOPhevCDEqscZMmyPn0C30E7B4474ec9SAr\n" +
      "Iankyv8txnxsgwWDx3CBaWhFSxzqTNiLDs23aKwzCNiFGqG/H/HlSpw=\n" +
      "-----END RSA PRIVATE KEY-----\n";
    private static final String verifyKey = "-----BEGIN PUBLIC KEY-----\n" +
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5JgjYNjLOeWC1Xf/NFcr\n" +
      "emS9peiQd3esa64KZ0BJue74bEtpN8CLmbeTD9NHvKzCg833cF81gkrkP/pkra7W\n" +
      "ZF+zNlHBDnO68D/tBkEAzPJYlFLLbMgvgL90fLbev4tlEUD59e0QGJQjIrcieOJS\n" +
      "oOBSc8SqhVN61pdzT3rTUx+pq+QPXpBor+HUOzRPpVfcTkwfxjVUTzJkSDI4pWS5\n" +
      "9+1NRVPhQBCPpG7j68VM60gJl+BnNzSI3gbvnh+UYrFvKA/fRkerAsz/Zy6LbGDA\n" +
      "FYEQjpphGyQmtsqsOndL9zBvfQCp5oT4hukBc3yIR6GVXDi0UURVjKtlYMMD4O+f\n" +
      "qwIDAQAB\n" +
      "-----END PUBLIC KEY-----";
    private BaseClientDetails defaultClient;
    private IdentityZone testZone;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private WebApplicationContext webApplicationContext;

    @BeforeEach
    void setSigningKeyAndDefaultClient() {
        setSigningKeyAndDefaultClient(signKey);
    }

    @Test
    void checkTokenKey() throws Exception {
        MvcResult result = mockMvc
          .perform(
            get("/token_key")
              .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
              .accept(MediaType.APPLICATION_JSON)
              .header("Authorization", getBasicAuth(defaultClient))
          )
          .andExpect(status().isOk())
          .andReturn();

        Map<String, Object> key = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        validateKey(key);
    }

    @Test
    void checkTokenKeyReturnETag() throws Exception {
        mockMvc.perform(
          get("/token_key")
            .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
            .accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isOk())
          .andExpect(header().string("ETag", any(String.class)))
          .andReturn();
    }

    @Test
    void checkTokenKeyReturns304IfResourceUnchanged() throws Exception {
        mockMvc.perform(
          get("/token_key")
            .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
            .header("If-None-Match", testZone.getLastModified().getTime()))
          .andExpect(status().isNotModified())
          .andReturn();
    }

    @Test
    void checkTokenKey_IsNotFromDefaultZone() throws Exception {
        MvcResult nonDefaultZoneResponse = mockMvc
          .perform(
            get("/token_key")
              .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
              .accept(MediaType.APPLICATION_JSON)
              .header("Authorization", getBasicAuth(defaultClient))
          )
          .andExpect(status().isOk())
          .andReturn();
        Map<String, Object> nonDefaultKey = JsonUtils.readValue(nonDefaultZoneResponse.getResponse().getContentAsString(), Map.class);
        VerificationKeyResponse nonDefaultKeyResponse = new VerificationKeyResponse(nonDefaultKey);

        MvcResult defaultZoneResponse = mockMvc
          .perform(
            get("/token_key")
              .accept(MediaType.APPLICATION_JSON)
              .header("Authorization", getBasicAuth(defaultClient))
          )
          .andExpect(status().isOk())
          .andReturn();

        Map<String, Object> defaultKey = JsonUtils.readValue(defaultZoneResponse.getResponse().getContentAsString(), Map.class);
        VerificationKeyResponse defaultKeyResponse = new VerificationKeyResponse(defaultKey);

        assertNotEquals(nonDefaultKeyResponse.getValue(), defaultKeyResponse.getValue());
    }

    @Test
    void checkTokenKey_WhenKeysAreAsymmetric_asAuthenticatedUser() throws Exception {
        BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(),
          "",
          "foo,bar",
          "client_credentials,password",
          "uaa.none");
        client.setClientSecret("secret");
        webApplicationContext.getBean(MultitenantClientServices.class).addClientDetails(client, testZone.getSubdomain());

        MvcResult result = mockMvc.perform(
          get("/token_key")
            .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
            .accept(MediaType.APPLICATION_JSON)
            .header("Authorization", getBasicAuth(client)))
          .andExpect(status().isOk())
          .andReturn();

        Map<String, Object> key = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        validateKey(key);
    }

    @Test
    void checkTokenKey_WhenKeysAreAsymmetric_asAuthenticatedUser_withoutCorrectScope() throws Exception {
        setSigningKeyAndDefaultClient("key");
        BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(),
          "",
          "foo,bar",
          "client_credentials,password",
          "uaa.none");
        client.setClientSecret("secret");
        webApplicationContext.getBean(MultitenantClientServices.class).addClientDetails(client, testZone.getSubdomain());

        mockMvc
          .perform(
            get("/token_key")
              .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
              .accept(MediaType.APPLICATION_JSON)
              .header("Authorization", getBasicAuth(client))
          )
          .andExpect(status().isForbidden())
          .andReturn();
    }

    @Test
    void checkTokenKey_asUnauthenticatedUser() throws Exception {
        MvcResult result = mockMvc
          .perform(
            get("/token_key")
              .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
              .accept(MediaType.APPLICATION_JSON)
          )
          .andExpect(status().isOk())
          .andReturn();

        Map<String, Object> key = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        validateKey(key);
    }

    @Test
    void checkTokenKeys() throws Exception {
        MvcResult result = mockMvc
          .perform(
            get("/token_keys")
              .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
              .accept(MediaType.APPLICATION_JSON)
              .header("Authorization", getBasicAuth(defaultClient))
          )
          .andExpect(status().isOk())
          .andReturn();

        Map<String, Object> keys = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        validateKeys(keys);
    }

    @Test
    void checkTokenKeysReturnETag() throws Exception {
        mockMvc.perform(
          get("/token_keys")
            .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
            .accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isOk())
          .andExpect(header().string("ETag", any(String.class)))
          .andReturn();
    }

    @Test
    void checkTokenKeysReturns304IfResourceUnchanged() throws Exception {
        mockMvc.perform(
          get("/token_keys")
            .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
            .header("If-None-Match", testZone.getLastModified().getTime()))
          .andExpect(status().isNotModified())
          .andReturn();
    }

    @Test
    void checkTokenKeys_asUnauthenticatedUser() throws Exception {
        MvcResult result = mockMvc
          .perform(
            get("/token_keys")
              .with(new SetServerNameRequestPostProcessor(testZone.getSubdomain() + ".localhost"))
              .accept(MediaType.APPLICATION_JSON)
          )
          .andExpect(status().isOk())
          .andReturn();

        Map<String, Object> keys = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        validateKeys(keys);
    }

    private void setSigningKeyAndDefaultClient(String signKey) {
        String subdomain = new RandomValueStringGenerator().generate().toLowerCase();
        IdentityZoneProvisioning provisioning = webApplicationContext.getBean(IdentityZoneProvisioning.class);
        testZone = new IdentityZone();
        testZone.setConfig(new IdentityZoneConfiguration());
        testZone.setId(subdomain);
        testZone.setSubdomain(subdomain);
        testZone.setName(subdomain);
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap("testKey", signKey));
        testZone.getConfig().setTokenPolicy(tokenPolicy);
        testZone = provisioning.create(testZone);

        defaultClient = new BaseClientDetails("app", "", "", "password", "uaa.resource");
        defaultClient.setClientSecret("appclientsecret");
        webApplicationContext.getBean(MultitenantJdbcClientDetailsService.class).addClientDetails(defaultClient, subdomain);
    }

    private String getBasicAuth(BaseClientDetails client) {
        return "Basic "
          + new String(Base64.encodeBase64((client.getClientId() + ":" + client.getClientSecret()).getBytes()));
    }

    private void validateKey(Map<String, Object> key) {
        Object kty = key.get("kty");
        assertNotNull(kty);
        assertTrue(kty instanceof String);
        assertEquals("RSA", kty);

        Object use = key.get("use"); //optional
        //values for use are
        //1. sig - key used to verify the signature
        //2. enc - key used to
        assertNotNull(use);
        assertTrue(use instanceof String);
        assertEquals("sig", use);


        Object key_ops = key.get("key_ops");
        //an String[] containing values like
        //sign, verify, encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits
        //should not be used together with 'use' (mutually exclusive)
        assertNull(key_ops);

        Object alg = key.get("alg");
        //optional - algorithm of key
        assertNotNull(alg);
        assertTrue(alg instanceof String);
        assertEquals("RS256", alg);

        Object kid = key.get("kid");
        //optional - indicates the id for a certain key
        //single key doesn't need one
        assertEquals("testKey", kid);

        Object x5u = key.get("x5u");
        //optional - URL that points to a X.509 key or certificate
        assertNull(x5u);

        Object x5c = key.get("x5c");
        //optional - contains a chain of one or more
        //PKIX certificate
        assertNull(x5c);

        Object x5t = key.get("x5t");
        //optional - x509 certificate SHA-1
        assertNull(x5t);

        Object x5tHashS256 = key.get("x5t#S256");
        //optional
        assertNull(x5tHashS256);

        Object actual = key.get("value");
        assertNotNull(actual);
        assertTrue(actual instanceof String);
        assertEquals(verifyKey, actual);


        Object e = key.get("e");
        assertNotNull(e);
        assertTrue(e instanceof String);
        assertEquals("AQAB", e);
        isUrlSafeBase64((String) e);

        Object n = key.get("n");
        assertNotNull(n);
        assertTrue(n instanceof String);
        isUrlSafeBase64((String) n);

    }

    private void validateKeys(Map<String, Object> response) {
        List<Map<String, Object>> keys = (List<Map<String, Object>>) response.get("keys");
        assertNotNull(keys);

        Map<String, ? extends Map<String, Object>> keysMap = keys.stream().collect(new MapCollector<>(k -> (String) k.get("kid"), k -> k));

        assertThat(keysMap, hasKey(is("testKey")));
        validateKey(keysMap.get("testKey"));
    }

    private void isUrlSafeBase64(String base64) {
        java.util.Base64.Encoder encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        java.util.Base64.Decoder decoder = java.util.Base64.getUrlDecoder();
        assertEquals(base64, encoder.encodeToString(decoder.decode(base64)));
    }

}
