package org.cloudfoundry.identity.uaa.oauth.jwk;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JsonWebKeyHelperTest {

    private static final String KEY = "{\"kty\":\"RSA\",\"kid\":\"%s\",\"e\":\"AQAB\",\"n\":\"AQAB\"}";

    @ParameterizedTest
    @CsvSource({"0", "1", "3", "250"})
    void countKeys_matchesDeserializedKeyCount(int count) {
        StringBuilder json = new StringBuilder("{\"other\":{\"keys\":[1,2]},\"keys\":[");
        for (int i = 0; i < count; i++) {
            json.append(i == 0 ? "" : ",").append(KEY.formatted("k" + i));
        }
        json.append("],\"trailing\":[{}]}");

        assertThat(JsonWebKeyHelper.countKeys(json.toString()))
                .isEqualTo(count)
                .isEqualTo(JsonWebKeyHelper.deserialize(json.toString()).getKeys().size());
    }

    @Test
    void countKeys_singleKeyWithoutKeysMember_countsAsOne() {
        String json = KEY.formatted("only");

        assertThat(JsonWebKeyHelper.countKeys(json)).isOne();
        assertThat(JsonWebKeyHelper.deserialize(json).getKeys()).hasSize(1);
    }

    @Test
    void countKeys_ignoresNestedKeysMembers() {
        String json = "{\"keys\":[{\"kty\":\"RSA\",\"keys\":[1,2,3],\"x\":{\"keys\":[4]}}]}";

        assertThat(JsonWebKeyHelper.countKeys(json)).isOne();
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "{\"keys\":[],\"keys\":[{\"kty\":\"RSA\"},{\"kty\":\"RSA\"}]}",
            "{\"keys\":[{\"kty\":\"RSA\"}],\"other\":1,\"keys\":[]}",
            "{\"keys\":null,\"keys\":[{\"kty\":\"RSA\"}]}"
    })
    void countKeys_duplicateTopLevelKeysMember_isRejected(String json) {
        assertThatThrownBy(() -> JsonWebKeyHelper.countKeys(json))
                .isInstanceOf(JsonUtils.JsonUtilException.class)
                .hasRootCauseMessage("Duplicate \"keys\" member in JWK set");
    }

    @Test
    void countKeys_escapedKeysPropertyName_isCountedLikeThePlainName() {
        String json = "{\"\\u006beys\":[%s,%s,%s]}".formatted(KEY.formatted("a"), KEY.formatted("b"), KEY.formatted("c"));

        assertThat(JsonWebKeyHelper.countKeys(json)).isEqualTo(3);
    }

    @Test
    void deserialize_escapedKeysPropertyName_isReadAsKeySet() {
        String json = "{\"\\u006beys\":[%s,%s,%s]}".formatted(KEY.formatted("a"), KEY.formatted("b"), KEY.formatted("c"));

        assertThat(JsonWebKeyHelper.deserialize(json).getKeys())
                .extracting(JsonWebKey::getKid)
                .containsExactly("a", "b", "c");
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "{\"kty\":\"RSA\",\"kid\":\"keys\",\"e\":\"AQAB\",\"n\":\"AQAB\"}",
            "{\"kty\":\"RSA\",\"kid\":\"k\",\"x\":{\"keys\":[1]},\"e\":\"AQAB\",\"n\":\"AQAB\"}"
    })
    void deserialize_singleKeyMentioningKeysBelowTopLevel_isReadAsSingleKey(String json) {
        assertThat(JsonWebKeyHelper.countKeys(json)).isOne();
        assertThat(JsonWebKeyHelper.deserialize(json).getKeys()).singleElement()
                .extracting(JsonWebKey::getKty).isEqualTo(JsonWebKey.KeyType.RSA);
    }

    @Test
    void countKeys_singleKeyWithHugeNestedMember_isRejected() {
        String json = "{\"kty\":\"RSA\",\"x\":[" + "{},".repeat(JsonWebKeyHelper.MAX_JWKS_JSON_VALUES) + "{}]}";

        assertThatThrownBy(() -> JsonWebKeyHelper.countKeys(json))
                .isInstanceOf(JsonUtils.JsonUtilException.class)
                .hasRootCauseMessage("JWK set document exceeds 10000 JSON values");
    }

    @Test
    void countKeys_documentAtValueLimit_isAccepted() {
        // Values counted: the root object and the keys array, then per KEY its object plus its 4 members
        // (kty, kid, e, n), then one per top-level scalar used to fill up to the limit exactly.
        int containerValues = 2;
        int valuesPerKey = 1 + 4;
        int keys = (JsonWebKeyHelper.MAX_JWKS_JSON_VALUES - containerValues) / valuesPerKey;
        int fillers = JsonWebKeyHelper.MAX_JWKS_JSON_VALUES - containerValues - keys * valuesPerKey;
        StringBuilder json = new StringBuilder("{");
        for (int i = 0; i < fillers; i++) {
            json.append("\"f").append(i).append("\":1,");
        }
        json.append("\"keys\":[");
        for (int i = 0; i < keys; i++) {
            json.append(i == 0 ? "" : ",").append(KEY.formatted("k" + i));
        }
        json.append("]}");

        assertThat(JsonWebKeyHelper.countKeys(json.toString())).isEqualTo(keys);
        assertThatThrownBy(() -> JsonWebKeyHelper.countKeys(json.insert(1, "\"oneTooMany\":1,").toString()))
                .hasRootCauseMessage("JWK set document exceeds 10000 JSON values");
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '\'', value = {
            "{\"keys\":[",
            "{\"keys\":[{",
            "{\"keys\":[{\"kty\":\"RSA\"",
            "{\"keys\":[{\"kty\":\"RSA\"},",
            "{\"keys\":",
            "{\"kty\":",
            "{\"kty\":\"RSA\",\"x\":{\"y\":[",
            "{\"kty\":\"RSA\""
    })
    void countKeys_truncatedDocument_throwsJsonUtilException(String json) {
        assertThatThrownBy(() -> JsonWebKeyHelper.countKeys(json))
                .isInstanceOf(JsonUtils.JsonUtilException.class);
    }

    @Test
    void countKeys_invalidJson_throwsJsonUtilException() {
        assertThatThrownBy(() -> JsonWebKeyHelper.countKeys("{\"keys\":[{]"))
                .isInstanceOf(JsonUtils.JsonUtilException.class);
    }
}
