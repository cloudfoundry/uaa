package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;
import org.springframework.security.jwt.codec.Codecs;

public abstract class CredentialIdTypeAbstractJWT implements CredentialIdType {
    protected enum Section {
        Header( 0 ),
        Headers( 0 ),
        Payload( 1 ),
        Claims( 1 ),
        Signature( 2 );

        private final int sectionNumber;

        Section( int sectionNumber ) {
            this.sectionNumber = sectionNumber;
        }

        static int sectionNumberFrom( String section, int max ) {
            section = StringUtils.normalizeToEmpty( section );
            if ( section.length() == 1 ) {
                char c = section.charAt( 0 );
                if ( ('0' <= c) && (c <= '9') ) {
                    return checkMax( max, c - '0', section );
                }
            } else {
                for ( Section value : values() ) {
                    if ( value.name().equalsIgnoreCase( section ) ) {
                        return checkMax( max, value.sectionNumber, section );
                    }
                }
            }
            throw new RateLimitingConfigException( "Unrecognized JWT section reference of: " + section );
        }

        private static int checkMax( int max, int value, String section ) {
            if ( value <= max ) {
                return value;
            }
            throw new RateLimitingConfigException( "JWT section '" + section + "' not acceptable" );
        }
    }

    protected static class SectionJWT extends AllJWT {
        final int section;

        public SectionJWT( int section ) {
            this.section = section;
        }

        @Override
        protected String from( JWTparts jp ) {
            return (section < jp.parts.length) ? jp.parts[section] : null;
        }
    }

    protected static class AllJWT implements AuthorizationCredentialIdExtractor {
        protected String from( JWTparts jp ) {
            return jp.token;
        }

        @Override
        public String mapAuthorizationToCredentialsID( RequestInfo info ) {
            JWTparts jp = JWTparts.from( info );
            return jp == null ? null : from( jp );
        }
    }

    protected static class JWTparts {
        String token;
        String[] parts;

        JWTparts( String pToken, String[] pParts ) {
            token = pToken;
            parts = pParts;
        }

        static JWTparts from( RequestInfo info ) {
            return info == null ? null : from( info.getAuthorizationHeader() );
        }

        static JWTparts from( String authorization ) { //. . . . . . . .1234567
            if ( (authorization != null) && (authorization.startsWith( "Bearer " ) || authorization.startsWith( "bearer " )) ) {
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
