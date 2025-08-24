package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CredentialIdTypeJWT extends CredentialIdTypeAbstractJWT {
    private final AuthorizationCredentialIdExtractorErrorLogger errorLogger;

    @Override
    public String key() {
        return "JWT";
    }

    @Override
    public AuthorizationCredentialIdExtractor factory(String keyTypeParameters) {
        keyTypeParameters = StringUtils.stripToEmpty(keyTypeParameters);
        if (keyTypeParameters.isEmpty()) {
            return new AllJWT();
        }
        String sectionRef = keyTypeParameters;
        String regex = null;
        // 'JWT:Claims+"email": *"(.*?)"' -> Claims+"email": *"(.*?)"
        int at = keyTypeParameters.indexOf('+'); // section reference and regex separator
        if (at != -1) {
            sectionRef = keyTypeParameters.substring(0, at);
            regex = StringUtils.stripToNull(keyTypeParameters.substring(at + 1));
        }
        int section = Section.sectionNumberFrom(sectionRef, 2);
        if (regex == null) {
            return new SectionJWT( section );
        }
        return new SectionRegexJWT( section, errorLogger, regex );
    }

    static class SectionRegexJWT extends SectionJWT {
        private final AuthorizationCredentialIdExtractorErrorLogger errorLogger;
        private final String regex;
        private final Pattern pattern;

        public SectionRegexJWT(int section,
                AuthorizationCredentialIdExtractorErrorLogger errorLogger,
                String regex) {
            super(section);
            this.errorLogger = errorLogger;
            this.regex = regex;
            pattern = Pattern.compile(regex);
        }

        @Override
        protected String from(JWTparts jp) {
            String section = super.from(jp); // Base64 encoded section
            if (section == null) {
                return null;
            }
            try {
                String decoded = decodeSection(section, this);
                Matcher m = pattern.matcher(decoded);
                if (!m.find()) {
                    return null;
                }
                int groups = m.groupCount();
                if (groups == 0) {
                    return null;
                }
                StringBuilder sb = new StringBuilder();
                for (int i = 1; i <= groups; i++) {
                    String group = StringUtils.stripToNull(m.group(i));
                    if (group != null) {
                        sb.append('|').append(group);
                    }
                }
                return sb.length() == 0 ? null : sb.append('|').toString();
            }
            catch (RuntimeException e) {
                errorLogger.log(e);
            }
            return null;
        }

        @Override
        public String toString() {
            return "JWT[" + section + "]:regex='" + regex + "'";
        }
    }
}
