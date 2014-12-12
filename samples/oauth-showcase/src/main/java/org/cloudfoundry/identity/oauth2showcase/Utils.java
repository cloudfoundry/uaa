package org.cloudfoundry.identity.oauth2showcase;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.oauth2.client.OAuth2ClientContext;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Utils {
    private static final ObjectMapper objectMapper = new ObjectMapper();
   
    public static String toPrettyJsonString(String json) {
        try {
            Object object = objectMapper.readValue(json, Object.class);
            return toPrettyJsonString(object);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
    }
    
    public static String toPrettyJsonString(Object object) {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(object);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
    }
    
    public static String getToken(OAuth2ClientContext clientContext) {
        if (clientContext.getAccessToken() != null) {
            String tokenBase64 = clientContext.getAccessToken().getValue().split("\\.")[1];
            return toPrettyJsonString(new String(Base64.decodeBase64(tokenBase64)));
        }
        return null;
    }
}
