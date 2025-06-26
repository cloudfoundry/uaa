package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

class JsonWebKeyTests {

    private static final String samplKeys = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-Microsoft.json");
    JsonWebKeySet<JsonWebKey> samlKeySet = JsonUtils.readValue(samplKeys, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
    });

    @Test
    void webKeyPublic() {
        // given
        Map<String, Object> jsonMap = Map.of("kid", "uaa-key", "kty", "RSA");
        JsonWebKey jsonWebKey = new JsonWebKey(jsonMap);
        jsonWebKey.setKid(samlKeySet.getKeys().getFirst().getKid());
        jsonWebKey.setX5t(samlKeySet.getKeys().getFirst().getX5t());
        // then
        assertThat(jsonWebKey.getKid()).isEqualTo(samlKeySet.getKeys().getFirst().getKid());
        assertThat(jsonWebKey.getX5t()).isEqualTo(samlKeySet.getKeys().getFirst().getX5t());
        assertThat(((ArrayList) samlKeySet.getKeySetMap().get("keys"))).hasSize(3);
    }

    @Test
    void webKeyPublicNoTypeException() {
        // given
        Map<String, Object> jsonMap = Map.of("kid", "uaa-key");
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new JsonWebKey(jsonMap));
    }
}
