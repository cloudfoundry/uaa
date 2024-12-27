package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CredentialIdTypeJWTjsonField extends CredentialIdTypeAbstractJWT {
    private final AuthorizationCredentialIdExtractorErrorLogger errorLogger;

    @Override
    public String key() {
        return "JWTjsonField";
    }

    @Override
    public AuthorizationCredentialIdExtractor factory(String keyTypeParameters) {
        // 'JWT:Claims:email'
        String[] sectionAndField = StringUtils.stripToEmpty(keyTypeParameters).split(":");
        String errorMsg;
        if (sectionAndField.length != 2) {
            errorMsg = sectionAndField.length + " values";
        } else {
            int section = Section.sectionNumberFrom(sectionAndField[0], 1);
            String fieldName = sectionAndField[1].trim();
            if (!fieldName.isEmpty()) {
                return new SectionFieldJWT( section, errorLogger, fieldName );
            }
            errorMsg = "NO field Name (after the ':')";
        }
        throw new RateLimitingConfigException( "Expected exactly two values to configure a JWTjsonField's" +
                " section and field name, but got " + errorMsg + " from: " + keyTypeParameters );
    }

    static class SectionFieldJWT extends SectionJWT {
        private final ObjectMapper mapper = new ObjectMapper();
        private final AuthorizationCredentialIdExtractorErrorLogger errorLogger;
        private final String field;

        public SectionFieldJWT(int section,
                AuthorizationCredentialIdExtractorErrorLogger errorLogger,
                String field) {
            super(section);
            this.errorLogger = errorLogger;
            this.field = field;
        }

        @Override
        protected String from(JWTparts jp) {
            String section = super.from(jp); // Base64 encoded section
            if (section == null) {
                return null;
            }
            String valueFound = null;
            try {
                String json = decodeSection(section, this);
                Map<?, ?> map = mapper.readValue(json, Map.class);
                Object value = map.get(field);
                if (value != null) {
                    valueFound = value.toString();
                }
            }
            catch (JsonProcessingException | RuntimeException e) {
                errorLogger.log(e);
            }
            return valueFound == null ? null : ("|" + valueFound + "|");
        }

        @Override
        public String toString() {
            return "JWT[" + section + "]:field='" + field + "'";
        }
    }
}
