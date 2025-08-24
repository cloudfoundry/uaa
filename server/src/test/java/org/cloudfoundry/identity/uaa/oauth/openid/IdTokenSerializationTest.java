package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.json.BasicJsonTester;
import org.springframework.boot.test.json.JsonContentAssert;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class IdTokenSerializationTest {
    private final BasicJsonTester json = new BasicJsonTester(getClass());

    private IdToken idToken;

    @BeforeEach
    void setup() {
        Set<String> amr = new HashSet<>();
        amr.add("amr1");
        amr.add("amr2");

        Set<String> acr = new HashSet<>();
        acr.add("acr1");
        acr.add("acr2");

        DateTimeUtils.setCurrentMillisFixed(1000L);

        idToken = new IdToken(
                "sub",
                List.of("aud"),
                "iss",
                DateTime.now().toDate(),
                DateTime.now().toDate(),
                DateTime.now().toDate(),
                amr,
                acr,
                "azp",
                "givenname",
                "familyname",
                1123L,
                "123",
                new HashSet<>(),
                new HashMap<>(),
                true,
                "nonce",
                "email",
                "client_id",
                "grant_type",
                "username",
                "myzid",
                "origin",
                "some-uuid",
                "revSig");
    }

    @AfterEach
    void teardown() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test
    void serializingIdToken() {
        String idTokenJsonString = JsonUtils.writeValueAsString(idToken);
        JsonContentAssert jsonContentAssert = assertThat(json.from(idTokenJsonString));
        jsonContentAssert.hasJsonPath("user_id")
                .hasJsonPath("sub")
                .hasJsonPath("given_name")
                .hasJsonPath("family_name")
                .hasJsonPath("phone_number")
                .hasJsonPath("user_attributes")
                .doesNotHaveJsonPath("authTime")
                .hasJsonPathValue("previous_logon_time", 1123)
                .hasJsonPathValue("previous_logon_time", 1123)
                .hasJsonPathValue("iat", 1)
                .hasJsonPathValue("exp", 1)
                .hasJsonPathValue("auth_time", 1)
                .hasJsonPathValue("email_verified", true)
                .hasJsonPathValue("nonce", "nonce")
                .hasJsonPathValue("email", "email")
                .hasJsonPathValue("cid", "client_id")
                .hasJsonPathValue("client_id", "client_id")
                .hasJsonPathValue("user_id", "sub")
                .hasJsonPathValue("grant_type", "grant_type")
                .hasJsonPathValue("user_name", "username")
                .hasJsonPathValue("zid", "myzid")
                .hasJsonPathValue("origin", "origin")
                .hasJsonPathValue("jti", "some-uuid")
                .hasJsonPathValue("rev_sig", "revSig");
        jsonContentAssert.extractingJsonPathArrayValue("acr.values").contains("acr1", "acr2");
        jsonContentAssert.extractingJsonPathArrayValue("amr").contains("amr1", "amr2");
        jsonContentAssert.extractingJsonPathArrayValue("scope").contains("openid");
    }

    @Test
    void serializingIdTokenOmitNullValues() {
        idToken = new IdToken(
                "sub",
                List.of("aud"),
                "iss",
                DateTime.now().toDate(),
                DateTime.now().toDate(),
                null,
                null,
                null,
                "azp",
                null,
                null,
                1123L,
                null,
                new HashSet<>(),
                new HashMap<>(),
                null,
                null,
                "",
                "",
                null,
                null,
                null,
                null,
                null,
                null);

        String idTokenJsonString = JsonUtils.writeValueAsString(idToken);
        assertThat(json.from(idTokenJsonString))
                .doesNotHaveJsonPath("given_name")
                .doesNotHaveJsonPath("family_name")
                .doesNotHaveJsonPath("phone_number")
                .doesNotHaveJsonPath("auth_time")
                .doesNotHaveJsonPath("amr")
                .doesNotHaveJsonPath("acr")
                .doesNotHaveJsonPath("zid")
                .doesNotHaveJsonPath("origin")
                .doesNotHaveJsonPath("jti")
                .doesNotHaveJsonPath("rev_sig");
    }
}