package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;
import org.springframework.security.jwt.codec.Codecs;

public class CredentialIdTypeJWT implements CredentialIdType {
    enum Section {
        Header( 0 ),
        Headers( 0 ),
        Payload( 1 ),
        Claims( 1 ),
        Signature( 2 );

        private final int sectionNumber;

        Section( int sectionNumber ) {
            this.sectionNumber = sectionNumber;
        }

        static int sectionNumberFrom( String section ) {
            section = StringUtils.normalizeToEmpty( section );
            if ( section.length() == 1 ) {
                char c = section.charAt( 0 );
                if ( ('0' <= c) && (c <= '9') ) {
                    return c - '0';
                }
            } else {
                for ( Section value : values() ) {
                    if ( value.name().equalsIgnoreCase( section ) ) {
                        return value.sectionNumber;
                    }
                }
            }
            throw new RateLimitingConfigException( "Unrecognized JWT section reference of: " + section );
        }
    }

    @Override
    public String key() {
        return "JWT";
    }

    @Override
    public AuthorizationCredentialIdExtractor factory( String keyTypeParameters ) {
        keyTypeParameters = StringUtils.normalizeToEmpty( keyTypeParameters );
        if ( keyTypeParameters.isEmpty() ) {
            return new AllJWT();
        }
        String sectionRef = keyTypeParameters;
        String regex = null;
        // 'JWT:Claims+"email": *"(.*?)"' -> Claims+"email": *"(.*?)"
        int at = keyTypeParameters.indexOf( '+' ); // section reference and regex separator
        if ( at != -1 ) {
            sectionRef = keyTypeParameters.substring( 0, at );
            regex = StringUtils.normalizeToNull( keyTypeParameters.substring( at + 1 ) );
        }
        int section = Section.sectionNumberFrom( sectionRef );
        if ( regex == null ) {
            return new SectionJWT( section );
        }
        return new SectionRegexJWT( section, regex );
    }

    static class SectionRegexJWT extends SectionJWT {
        private final String regex;
        private final Pattern pattern;

        public SectionRegexJWT( int section, String regex ) {
            super( section );
            this.regex = regex;
            pattern = Pattern.compile( regex );
        }

        @Override
        protected String from( JWTparts jp ) {
            String section = super.from( jp ); // Base64 encoded section
            if ( section == null ) {
                return null;
            }
            section = decodeSection( section, this ); // can throw an RTE
            Matcher m = pattern.matcher( section );
            if ( !m.find() ) {
                return null;
            }
            int groups = m.groupCount();
            if ( groups == 0 ) {
                return null;
            }
            StringBuilder sb = new StringBuilder();
            for ( int i = 1; i <= groups; i++ ) {
                String group = StringUtils.normalizeToNull( m.group( i ) );
                if ( group != null ) {
                    sb.append( '|' ).append( group );
                }
            }
            return (sb.length() == 0) ? null : sb.append( '|' ).toString();
        }

        @Override
        public String toString() {
            return "SectionRegexJWT{" + "regex='" + regex + '\'' +
                   ", pattern=" + pattern +
                   ", section=" + section +
                   '}';
        }
    }

    static class SectionJWT extends AllJWT {
        final int section;

        public SectionJWT( int section ) {
            this.section = section;
        }

        @Override
        protected String from( JWTparts jp ) {
            return (section < jp.parts.length) ? jp.parts[section] : null;
        }
    }

    static class AllJWT implements AuthorizationCredentialIdExtractor {
        protected String from( JWTparts jp ) {
            return jp.token;
        }

        @Override
        public String mapAuthorizationToCredentialsID( RequestInfo info ) {
            JWTparts jp = JWTparts.from( info );
            return jp == null ? null : from( jp );
        }
    }

    static class JWTparts {
        String token;
        String[] parts;

        JWTparts( String pToken, String[] pParts ) {
            token = pToken;
            parts = pParts;
        }

        static JWTparts from( RequestInfo info ) {
            return info == null ? null : from( info.getAuthorizationHeader() );
        }

        static JWTparts from( String authorization ) { // . . . . . . .1234567
            if ( (authorization != null) && authorization.startsWith( "Bearer " ) ) {
                String token = authorization.substring( 7 ).trim();
                String[] parts = token.split( "\\." );
                if ( (3 <= parts.length) && looksOK( parts[0] ) && looksOK( parts[1] ) && looksOK( parts[2] ) ) {
                    return new JWTparts( token, parts );
                }
            }
            return null;
        }

        private static boolean looksOK( String part ) {
            return part.length() == part.trim().length();
        }
    }

    // Pulled out so could Suppress "deprecation" Warnings
    @SuppressWarnings("deprecation")
    static String decodeSection( String section, Object toStringForException ) {
        try {
            byte[] bytes = Codecs.b64UrlDecode( section );
            return Codecs.utf8Decode( bytes );
        }
        catch ( RuntimeException e ) {
            throw new RateLimitingConfigException(
                    e.getMessage() + " | with: " + toStringForException + " | sectionText: " + section, e );
        }
    }
}
