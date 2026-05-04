package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class UaaClientTest {

    @Test
    void getClientJwtConfiguration_includesTopLevelJwtCredsFromAdditionalInformation() {
        Map<String, Object> addl = new HashMap<>();
        addl.put(ClientJwtConfiguration.JWT_CREDS, JsonUtils.readValue(
                "[{\"iss\":\"http://localhost/uaa/oauth/token\",\"sub\":\"c1\",\"aud\":\"c1\"}]", List.class));
        UaaClient c = new UaaClient("cid", "sec", List.of(new SimpleGrantedAuthority("uaa.none")), addl, null);
        ClientJwtConfiguration j = c.getClientJwtConfiguration();
        assertThat(j.getClientJwtCredentials()).isNotNull().hasSize(1);
        assertThat(j.getClientJwtCredentials().get(0).getIssuer()).isEqualTo("http://localhost/uaa/oauth/token");
    }

    @Test
    void getClientJwtConfiguration_mergesClientJwtConfigStringWithAdditionalJwtCreds() {
        String cfg = "{\"jwt_creds\":[{\"iss\":\"http://a\",\"sub\":\"b\"}]}";
        Map<String, Object> addl = new HashMap<>();
        addl.put(ClientJwtConfiguration.JWT_CREDS, JsonUtils.readValue(
                "[{\"iss\":\"http://c\",\"sub\":\"d\"}]", List.class));
        UaaClient c = new UaaClient("cid", "sec", List.of(new SimpleGrantedAuthority("uaa.none")), addl, cfg);
        ClientJwtConfiguration j = c.getClientJwtConfiguration();
        assertThat(j.getClientJwtCredentials()).hasSize(2);
    }

    @Test
    void getClientJwtConfiguration_includesNestedClientJwtConfigInAdditional() {
        Map<String, Object> inner = new HashMap<>();
        inner.put(ClientJwtConfiguration.JWT_CREDS, JsonUtils.readValue("[{\"iss\":\"http://n\",\"sub\":\"n\"}]", List.class));
        Map<String, Object> addl = new HashMap<>();
        addl.put("client_jwt_config", inner);
        UaaClient c = new UaaClient("cid", "sec", List.of(new SimpleGrantedAuthority("uaa.none")), addl, null);
        assertThat(c.getClientJwtConfiguration().getClientJwtCredentials()).hasSize(1);
    }

    @Test
    void mergeMatchesSyncWithExisting_twoDistinctCredentials() {
        String iss = "http://localhost:8080/uaa/oauth/token";
        UaaClient existing = new UaaClient("id", "s", List.of(new SimpleGrantedAuthority("uaa.none")),
                new HashMap<>(), "{\"jwt_creds\":[{\"iss\":\"" + iss + "\",\"sub\":\"first\"}]}");
        UaaClient input = new UaaClient("id", "s", List.of(new SimpleGrantedAuthority("uaa.none")),
                new HashMap<>(Map.of(ClientJwtConfiguration.JWT_CREDS, "[{\"iss\":\"" + iss + "\",\"sub\":\"second\"}]")),
                null);
        ClientJwtConfiguration merged = ClientJwtConfiguration.merge(
                existing.getClientJwtConfiguration(), input.getClientJwtConfiguration(), false);
        assertThat(merged.getClientJwtCredentials()).hasSize(2);
    }
}
