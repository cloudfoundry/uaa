package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

class JsonWebKeyTests {

    private static final String samplKeys = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-Microsoft.json");
    JsonWebKeySet<JsonWebKey> samlKeySet = JsonUtils.readValue(samplKeys, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
    });

    @Test
    void testWebKeyPublic() {
        // given
        Map<String, Object> jsonMap = Map.of("kid", "uaa-key", "kty", "RSA");
        JsonWebKey jsonWebKey = new JsonWebKey(jsonMap);
        jsonWebKey.setKid(samlKeySet.getKeys().get(0).getKid());
        jsonWebKey.setX5t(samlKeySet.getKeys().get(0).getX5t());
        // then
        assertEquals(samlKeySet.getKeys().get(0).getKid(), jsonWebKey.getKid());
        assertEquals(samlKeySet.getKeys().get(0).getX5t(), jsonWebKey.getX5t());
        assertEquals(3, ((ArrayList) samlKeySet.getKeySetMap().get("keys")).size());
    }

    @Test
    void testWebKeyPublicNoTypeException() {
        // given
        Map<String, Object> jsonMap = Map.of("kid", "uaa-key");
        assertThrows(IllegalArgumentException.class, () -> new JsonWebKey(jsonMap));
    }

}
