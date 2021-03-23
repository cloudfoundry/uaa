package org.cloudfoundry.identity.uaa.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.util.StringUtils;

import java.util.Map;

public class AuthorizationAttributesParser {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * This method searches the authorities in the request for
     * additionalAuthorizationAttributes
     * and returns a map of these attributes that will later be added to the
     * token
     *
     * @param authoritiesJson
     * @return
     */
    public Map<String, String> getAdditionalAuthorizationAttributes(String authoritiesJson) {
        if (StringUtils.hasLength(authoritiesJson)) {
            try {
                Map<String, Object> authorities = JsonUtils.readValue(authoritiesJson, new TypeReference<>() {
                });
                Object az_attr = authorities.get("az_attr");
                if (az_attr == null)
                    return null;
                // validate az_attr content with Map<String, String>>

                return JsonUtils.readValue(JsonUtils.writeValueAsBytes(az_attr), new TypeReference<>() {
                });
            } catch (Throwable t) {
                logger.error("Unable to read additionalAuthorizationAttributes", t);
            }
        }

        return null;
    }
}
