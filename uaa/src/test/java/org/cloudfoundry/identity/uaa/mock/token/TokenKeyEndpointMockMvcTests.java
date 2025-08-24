package org.cloudfoundry.identity.uaa.mock.token;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class TokenKeyEndpointMockMvcTests {

    private static final String SIGN_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpQIBAAKCAQEA5JgjYNjLOeWC1Xf/NFcremS9peiQd3esa64KZ0BJue74bEtp
            N8CLmbeTD9NHvKzCg833cF81gkrkP/pkra7WZF+zNlHBDnO68D/tBkEAzPJYlFLL
            bMgvgL90fLbev4tlEUD59e0QGJQjIrcieOJSoOBSc8SqhVN61pdzT3rTUx+pq+QP
            XpBor+HUOzRPpVfcTkwfxjVUTzJkSDI4pWS59+1NRVPhQBCPpG7j68VM60gJl+Bn
            NzSI3gbvnh+UYrFvKA/fRkerAsz/Zy6LbGDAFYEQjpphGyQmtsqsOndL9zBvfQCp
            5oT4hukBc3yIR6GVXDi0UURVjKtlYMMD4O+fqwIDAQABAoIBAQCi8VtOflomc9XV
            ygpMydIBFWwlpefMcK6jttRNkwK6mX/U2dAvYH1h3fvi7OyWreKdRySYohUnQbD/
            dcFsGFNUCu9Yyd++KHpZJIgUzCMA88J2P6onaW6K7G3hNA0FJhytts42IXw2uOlu
            pnHZDyJs8Fl1kfsmvEG0UxJr1hZqia9QbyylQcsuBGz82EIrGYXSkHJgzlklcMSH
            WSn5JfJ8W8gpD0NwMnsdK3udXy8HNp6iWTvkJhot8qV86VO/V9vttj+/4eNioMSR
            eSVsO/1vGk10glX2bxwHPUy3wrAwgXbtOUSpkG9qDJ7qXHKkR7Pucjbq30AIu7VK
            BsyRBv2RAoGBAPg0exT7ZmQFxOyHA260wEvdPh6mGRP5ZxwYJ9h35kiyuZPoMHRL
            9IPOSMJdHXvxnOhE0Y3/oFlchvBbrnwo1JHo4B61lGSgvxu84JaDNdMETpKS7hS0
            f1T1IQJsuRKZXllTd8pemKkpU4GlbQlpaAWZlNqjn1bs66ecu+o4KkWjAoGBAOvF
            /bu4g2lk5Y6CYEO1xsfZjVVaLEDXKAVWBjyLd084nlA/IJsrb7xVg0KR3jFKTb7k
            ZRNaTOeoJASLcqcgFNHGIxGhdzkj8rlDzrSNGGT1fdm97NQrkCmdtNfCSwR7qU6m
            9fFoYoq+nmvCUJfK8x1QeqTW2+ToApvL4rhxv45ZAoGBALUl4Fq87Mq9Zy7VjwzC
            QMJds5O81/q7AKUBgDs9rsWKI2Uuhgaq1MdJy9KHERi/iyv95g9D7OyrWhScZSla
            x2HCW6guECKtKy18WVGga60ZrJrPP5G+9lu0GCZj4WMQqkp5X6lEBxkW/0pUyNKg
            qnnD0F8OIiHYAlmvS3qzCS8PAoGAdntqxPk2YLJpgbIW+i/REwFKuwezkWoOHJBc
            VfSoIlGLjTwMAK5VWkmGyt9Oz2pNo45XFOCeIRQn9Xi2RzIiBEETwnpn1XkxMtTW
            fXkiNyn+8ns1FnJF4gP0qzBiToBuVq4kjgos6xhbuD9QDNfaUHLvDwNCQcgt92kA
            KDxRTRECgYEA6ClxlKmBV7Y++PnlJjsXFGUC1Pk3HX/YBxXWsJgdyPvyxNEPmYc9
            YCencbzky95AQIC+isTAQOvk59WeNjOPhevCDEqscZMmyPn0C30E7B4474ec9SAr
            Iankyv8txnxsgwWDx3CBaWhFSxzqTNiLDs23aKwzCNiFGqG/H/HlSpw=
            -----END RSA PRIVATE KEY-----
            """;
    private static final String VERIFY_KEY = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5JgjYNjLOeWC1Xf/NFcr
            emS9peiQd3esa64KZ0BJue74bEtpN8CLmbeTD9NHvKzCg833cF81gkrkP/pkra7W
            ZF+zNlHBDnO68D/tBkEAzPJYlFLLbMgvgL90fLbev4tlEUD59e0QGJQjIrcieOJS
            oOBSc8SqhVN61pdzT3rTUx+pq+QPXpBor+HUOzRPpVfcTkwfxjVUTzJkSDI4pWS5
            9+1NRVPhQBCPpG7j68VM60gJl+BnNzSI3gbvnh+UYrFvKA/fRkerAsz/Zy6LbGDA
            FYEQjpphGyQmtsqsOndL9zBvfQCp5oT4hukBc3yIR6GVXDi0UURVjKtlYMMD4O+f
            qwIDAQAB
            -----END PUBLIC KEY-----""";

    private UaaClientDetails defaultClient;
    private IdentityZone testZone;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private WebApplicationContext webApplicationContext;

    @BeforeEach
    void setSigningKeyAndDefaultClient() {
        setSigningKeyAndDefaultClient(SIGN_KEY);
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

        assertThat(defaultKeyResponse.getValue()).isNotEqualTo(nonDefaultKeyResponse.getValue());
    }

    @Test
    void checkTokenKey_WhenKeysAreAsymmetric_asAuthenticatedUser() throws Exception {
        UaaClientDetails client = new UaaClientDetails(new RandomValueStringGenerator().generate(),
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
        UaaClientDetails client = new UaaClientDetails(new RandomValueStringGenerator().generate(),
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

        defaultClient = new UaaClientDetails("app", "", "", "password", "uaa.resource");
        defaultClient.setClientSecret("appclientsecret");
        webApplicationContext.getBean(MultitenantJdbcClientDetailsService.class).addClientDetails(defaultClient, subdomain);
    }

    private String getBasicAuth(UaaClientDetails client) {
        return "Basic "
                + new String(Base64.encodeBase64((client.getClientId() + ":" + client.getClientSecret()).getBytes()));
    }

    private void validateKey(Map<String, Object> key) {
        Object kty = key.get("kty");
        assertThat(kty)
                .isInstanceOf(String.class)
                .isEqualTo("RSA");

        Object use = key.get("use"); //optional
        //values for use are
        //1. sig - key used to verify the signature
        //2. enc - key used to
        assertThat(use)
                .isInstanceOf(String.class)
                .isEqualTo("sig");

        Object keyOps = key.get("key_ops");
        //an String[] containing values like
        //sign, verify, encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits
        //should not be used together with 'use' (mutually exclusive)
        assertThat(keyOps).isNull();

        Object alg = key.get("alg");
        //optional - algorithm of key
        assertThat(alg)
                .isInstanceOf(String.class)
                .isEqualTo("RS256");

        Object kid = key.get("kid");
        //optional - indicates the id for a certain key
        //single key doesn't need one
        assertThat(kid).isEqualTo("testKey");

        Object x5u = key.get("x5u");
        //optional - URL that points to a X.509 key or certificate
        assertThat(x5u).isNull();

        Object x5c = key.get("x5c");
        //optional - contains a chain of one or more
        //PKIX certificate
        assertThat(x5c).isNull();

        Object x5t = key.get("x5t");
        //optional - x509 certificate SHA-1
        assertThat(x5t).isNull();

        Object x5tHashS256 = key.get("x5t#S256");
        //optional
        assertThat(x5tHashS256).isNull();

        Object actual = key.get("value");
        assertThat(actual).isInstanceOf(String.class)
                .isEqualTo(VERIFY_KEY);

        Object e = key.get("e");
        assertThat(e).isInstanceOf(String.class)
                .isEqualTo("AQAB");
        isUrlSafeBase64((String) e);

        Object n = key.get("n");
        assertThat(n).isInstanceOf(String.class);
        isUrlSafeBase64((String) n);

    }

    private void validateKeys(Map<String, Object> response) {
        List<Map<String, Object>> keys = (List<Map<String, Object>>) response.get("keys");
        assertThat(keys).isNotNull();

        Map<String, ? extends Map<String, Object>> keysMap = keys.stream().collect(new MapCollector<>(k -> (String) k.get("kid"), k -> k));

        assertThat(keysMap).containsKey("testKey");
        validateKey(keysMap.get("testKey"));
    }

    private void isUrlSafeBase64(String base64) {
        java.util.Base64.Encoder encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        java.util.Base64.Decoder decoder = java.util.Base64.getUrlDecoder();
        assertThat(encoder.encodeToString(decoder.decode(base64))).isEqualTo(base64);
    }
}
