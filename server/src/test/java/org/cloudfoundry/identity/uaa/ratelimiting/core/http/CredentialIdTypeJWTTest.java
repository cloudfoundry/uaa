package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.jwt.codec.Codecs;

import static org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public class CredentialIdTypeJWTTest {
    public static final String EMAIL = "devin@example.com";
    public static final String JSON_HEADER = "{ \"alg\": \"HS256\", \"typ\": \"JWT\" }";
    public static final String JSON_CLAIMS = "{ \"loggedInAs\": \"admin\", \"email\": \"" + EMAIL + "\", \"iat\": 1422779638 }";
    public static final String RAW_SIGNATURE = "The quick brown fox jumped over the lazy moon‼"; // any bytes... note non-ascii char
    public static final String RAW_4th_SECTION = "No clue what goes in here";

    public static final String b64section_HEADER = encodeSection( JSON_HEADER );
    public static final String b64section_CLAIMS = encodeSection( JSON_CLAIMS );
    public static final String b64section_SIGNATURE = encodeSection( RAW_SIGNATURE );
    public static final String b64section_4th_SECTION = encodeSection( RAW_4th_SECTION );

    public static final String JWT2 = b64section_HEADER + "." + b64section_CLAIMS; // 1 dot

    public static final String JWT3 = JWT2 + "." + b64section_SIGNATURE; // 2 dots

    public static final String JWT4 = JWT3 + "." + b64section_4th_SECTION; // 3 dots

    public static String AUTH_HEADER_VALUE_PREFIX = "Bearer ";

    public static String AUTH_HEADER_VALUE_JWT4 = AUTH_HEADER_VALUE_PREFIX + JWT4;

    private static final CredentialIdTypeJWT credentialIdType = new CredentialIdTypeJWT();

    RequestInfo requestInfo = Mockito.mock( RequestInfo.class );

    @Test
    public void roundTripDecode() {
        String header = decodeSection( b64section_HEADER, "header" );
        String claims = decodeSection( b64section_CLAIMS, "claims" );
        String signature = decodeSection( b64section_SIGNATURE, "signature" );
        String fourth = decodeSection( b64section_4th_SECTION, "fourth" );

        assertEquals( JSON_HEADER, header );
        assertEquals( JSON_CLAIMS, claims );
        assertEquals( RAW_SIGNATURE, signature );
        assertEquals( RAW_4th_SECTION, fourth );
    }

    @Test
    public void key() {
        assertEquals( "JWT", credentialIdType.key() );
    }

    @Test
    public void checkJWTparts() {
        assertNull( JWTparts.from( (RequestInfo)null ) );
        assertNull( JWTparts.from( (String)null ) );
        assertNull( JWTparts.from( "!" + AUTH_HEADER_VALUE_PREFIX + JWT3 ), "Not 'Bearer '" );
        assertNull( JWTparts.from( AUTH_HEADER_VALUE_PREFIX + b64section_HEADER ), "Only 1 section" );
        assertNull( JWTparts.from( AUTH_HEADER_VALUE_PREFIX + JWT2 ), "Only 2 sections" );
        assertNull( JWTparts.from( AUTH_HEADER_VALUE_PREFIX + JWT2 + " ." + b64section_SIGNATURE ), "space next to dot" );
        JWTparts parts = JWTparts.from( AUTH_HEADER_VALUE_PREFIX + JWT3 );
        assertNotNull( parts, "JWTparts" );
        assertEquals( JWT3, parts.token );
        String[] sections = parts.parts;
        assertNotNull( sections, "JWTparts.parts" );
        assertEquals( 3, sections.length );
        assertEquals( 3, sections.length );
        assertEquals( b64section_HEADER, sections[0], "header" );
        assertEquals( b64section_CLAIMS, sections[1], "claims" );
        assertEquals( b64section_SIGNATURE, sections[2], "signature" );
    }

    @Test
    public void factoryFlavors() {
        checkFlavor( null, AllJWT.class, JWT4 );
        checkFlavor( "", AllJWT.class, JWT4 );
        checkFlavor( " ", AllJWT.class, JWT4 );
        checkFlavor( " 0 ", SectionJWT.class, b64section_HEADER );
        checkFlavor( "header", SectionJWT.class, b64section_HEADER );
        checkFlavor( "HEADERS", SectionJWT.class, b64section_HEADER );
        checkFlavor( "1", SectionJWT.class, b64section_CLAIMS );
        checkFlavor( "Payload", SectionJWT.class, b64section_CLAIMS );
        checkFlavor( "claimS", SectionJWT.class, b64section_CLAIMS );
        checkFlavor( "2", SectionJWT.class, b64section_SIGNATURE );
        checkFlavor( "signaTure", SectionJWT.class, b64section_SIGNATURE );
        checkFlavor( "3", SectionJWT.class, b64section_4th_SECTION );
        checkFlavor( "4", SectionJWT.class, null );
        checkFlavor( "9", SectionJWT.class, null );
        checkFlavor( "Claims+\"email\"\\s*:\\s*\"(.*?)\"", SectionRegexJWT.class, "|" + EMAIL + "|" );

        AuthorizationCredentialIdExtractor factory = credentialIdType.factory( "claims" );
        when( requestInfo.getAuthorizationHeader() ).thenReturn( null );
        assertNull( factory.mapAuthorizationToCredentialsID( requestInfo ) );
    }

    private void checkFlavor( String postKeyConfig, Class<?> credentialIdExtractorClass, String extractedCredential ) {
        AuthorizationCredentialIdExtractor factory = credentialIdType.factory( postKeyConfig );
        assertSame( credentialIdExtractorClass, factory.getClass() );
        when( requestInfo.getAuthorizationHeader() ).thenReturn( AUTH_HEADER_VALUE_JWT4 );
        String id = factory.mapAuthorizationToCredentialsID( requestInfo );
        assertEquals( extractedCredential, id, "Id mis-match from: " + postKeyConfig );
    }

    // Pulled out so could Suppress "deprecation" Warnings
    @SuppressWarnings("deprecation")
    static String encodeSection( String section ) {
        return Codecs.utf8Decode( Codecs.b64UrlEncode( section ) );
    }
}