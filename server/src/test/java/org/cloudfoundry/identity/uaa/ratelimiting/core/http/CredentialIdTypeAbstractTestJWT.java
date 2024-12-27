package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT.JWTparts;
import static org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT.decodeSection;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public abstract class CredentialIdTypeAbstractTestJWT<CitJWT extends CredentialIdTypeAbstractJWT> {
    public static final String EMAIL_DEVIN = "devin@example.com";
    public static final String SIMPLE_CLAIMS_EMAIL_PREFIX = "{ \"loggedInAs\": \"admin\", \"email\": \"";
    public static final String SIMPLE_CLAIMS_EMAIL_SUFFIX = "\", \"iat\": 1422779638 }";

    public static final String JSON_HEADER = "{ \"alg\": \"HS256\", \"typ\": \"JWT\" }";
    public static final String JSON_CLAIMS = SIMPLE_CLAIMS_EMAIL_PREFIX + EMAIL_DEVIN + SIMPLE_CLAIMS_EMAIL_SUFFIX;
    public static final String RAW_SIGNATURE = "The quick brown fox jumped over the lazy moon‼"; // any bytes... note non-ascii char
    public static final String RAW_4th_SECTION = "No clue what goes in here";

    public static final String b64section_HEADER = encodeSection(JSON_HEADER);
    public static final String b64section_CLAIMS = encodeSection(JSON_CLAIMS);
    public static final String b64section_SIGNATURE = encodeSection(RAW_SIGNATURE);
    public static final String b64section_4th_SECTION = encodeSection(RAW_4th_SECTION);

    public static final String JWT2 = b64section_HEADER + "." + b64section_CLAIMS; // 1 dot

    public static final String JWT3 = JWT2 + "." + b64section_SIGNATURE; // 2 dots

    public static final String JWT4 = JWT3 + "." + b64section_4th_SECTION; // 3 dots

    public static final String JWT = JWT3;

    public static String AUTH_HEADER_VALUE_PREFIX_UC = "Bearer ";
    public static String AUTH_HEADER_VALUE_PREFIX_LC = "bearer ";

    protected final List<Exception> exceptionCollector = new ArrayList<>();

    protected RequestInfo requestInfo = Mockito.mock(RequestInfo.class);

    protected final String emailFromClaims;
    protected final CitJWT credentialIdType;

    public CredentialIdTypeAbstractTestJWT(String emailFromClaims,
            Function<AuthorizationCredentialIdExtractorErrorLogger, CitJWT> function) {
        this.emailFromClaims = emailFromClaims;
        credentialIdType = function.apply(exceptionCollector::add);
    }

    @Test
    public void roundTripDecode() {
        String header = decodeSection(b64section_HEADER, "header");
        String claims = decodeSection(b64section_CLAIMS, "claims");
        String signature = decodeSection(b64section_SIGNATURE, "signature");
        String fourth = decodeSection(b64section_4th_SECTION, "fourth");

        assertEquals(JSON_HEADER, header);
        assertEquals(JSON_CLAIMS, claims);
        assertEquals(RAW_SIGNATURE, signature);
        assertEquals(RAW_4th_SECTION, fourth);
    }

    @Test
    public void checkJWTparts() {
        assertNull(JWTparts.from((RequestInfo) null));
        assertNull(JWTparts.from((String) null));
        assertNull(JWTparts.from("!" + AUTH_HEADER_VALUE_PREFIX_UC + JWT), "Not 'Bearer '");
        assertNull(JWTparts.from(AUTH_HEADER_VALUE_PREFIX_UC + b64section_HEADER), "Only 1 section");
        assertNull(JWTparts.from(AUTH_HEADER_VALUE_PREFIX_UC + JWT2), "Only 2 sections");
        assertNull(JWTparts.from(AUTH_HEADER_VALUE_PREFIX_UC + JWT2 + " ." + b64section_SIGNATURE), "space next to dot");
        checkJWTparts(AUTH_HEADER_VALUE_PREFIX_UC);
        checkJWTparts(AUTH_HEADER_VALUE_PREFIX_LC);
    }

    private void checkJWTparts(String authHeaderValuePrefix) {
        JWTparts parts = JWTparts.from(authHeaderValuePrefix + JWT);
        assertNotNull(parts, authHeaderValuePrefix + "JWTparts");
        assertEquals(JWT, parts.token, authHeaderValuePrefix + "JWTparts.token");
        String[] sections = parts.parts;
        assertNotNull(sections, "JWTparts.parts.sections");
        assertEquals(3, sections.length, authHeaderValuePrefix + "JWTparts.sections");
        assertEquals(b64section_HEADER, sections[0], authHeaderValuePrefix + "JWTparts.header");
        assertEquals(b64section_CLAIMS, sections[1], authHeaderValuePrefix + "JWTpart.claims");
        assertEquals(b64section_SIGNATURE, sections[2], authHeaderValuePrefix + "JWTpart.signature");
    }

    @Test
    public void checkEmailFromClaims() {
        AuthorizationCredentialIdExtractor factory = credentialIdType.factory(emailFromClaims);

        when(requestInfo.getAuthorizationHeader()).thenReturn(
                AUTH_HEADER_VALUE_PREFIX_UC +
                        "eyJhbGciOiJIUzI1NiIsImprdSI6Imh0dHBzOi8vbG9jYWxob3N0OjgwODAvdWFhL3Rva2VuX2tleXMiLCJraWQiOiJsZWdhY3ktdG9rZW4ta2V5IiwidHlwIjoiSldUIn0" +
                        ".eyJqdGkiOiI0NGQ1OTQzY2NmYWI0YmJhODdjYTgyMGU1NjJkMWIzZCIsInN1YiI6ImFlYzAzNzE0LTJkN2YtNGQ1OS1hMGVjLTMzMmQyY2QzYTZiNCIsInNjb3BlIjpbInVhYS51c2VyIl0" +
                        "sImNsaWVudF9pZCI6ImNmIiwiY2lkIjoiY2YiLCJhenAiOiJjZiIsImdyYW50X3R5cGUiOiJwYXNzd29yZCIsInVzZXJfaWQiOiJhZWMwMzcxNC0yZDdmLTRkNTktYTBlYy0zMzJkMmNkM2E" +
                        "2YjQiLCJvcmlnaW4iOiJ1YWEiLCJ1c2VyX25hbWUiOiJtYXJpc3NhIiwiZW1haWwiOiJtYXJpc3NhQHRlc3Qub3JnIiwiYXV0aF90aW1lIjoxNjUyOTkwNTk4LCJyZXZfc2lnIjoiNTkxMzI" +
                        "5NjMiLCJpYXQiOjE2NTI5OTA1OTgsImV4cCI6MTY1MzAzMzc5OCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3VhYS9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF1ZCI6WyJjZiIsInVhYSJdfQ" +
                        ".Z6v-yGQ9BLS67H8KBnZ31sAHCXFs2O5A7zgNrNErPiU");
        String id = factory.mapAuthorizationToCredentialsID(requestInfo);
        assertEquals("|" + "marissa@test.org" + "|", id, "Id mis-match from sample");

        when(requestInfo.getAuthorizationHeader()).thenReturn(AUTH_HEADER_VALUE_PREFIX_LC + JWT4);
        id = factory.mapAuthorizationToCredentialsID(requestInfo);
        assertEquals("|" + EMAIL_DEVIN + "|", id, "Id mis-match from default 3 dot JWT");

        for (String email : SAMPLE_EMAILS) {
            String jwt = "bad." + encodeSection(SIMPLE_CLAIMS_EMAIL_PREFIX + email + SIMPLE_CLAIMS_EMAIL_SUFFIX) + ".bad-bad";
            when(requestInfo.getAuthorizationHeader()).thenReturn(AUTH_HEADER_VALUE_PREFIX_UC + jwt);
            id = factory.mapAuthorizationToCredentialsID(requestInfo);
            assertEquals("|" + email + "|", id);
            System.out.println(email + " -> " + jwt);
        }
    }

    protected void checkFlavor(String postKeyConfig, Class<?> credentialIdExtractorClass, String extractedCredential) {
        AuthorizationCredentialIdExtractor factory = credentialIdType.factory(postKeyConfig);

        assertSame(credentialIdExtractorClass, factory.getClass());
        when(requestInfo.getAuthorizationHeader()).thenReturn(AUTH_HEADER_VALUE_PREFIX_UC + JWT);
        String id = factory.mapAuthorizationToCredentialsID(requestInfo);
        assertEquals(extractedCredential, id, "Id mis-match from: " + postKeyConfig);
    }

    // Pulled out so could Suppress "deprecation" Warnings
    @SuppressWarnings("deprecation")
    static String encodeSection(String section) {
        return Base64URL.encode(section).toString();
    }

    // 24 Sample "simple and valid format" emails
    static final String[] SAMPLE_EMAILS = {
            "prettyandsimple@example.com",
            "very.common@example.com",
            "disposable.style.email.with+symbol@example.com",
            "other.email-with-dash@example.com",
            "fully-qualified-domain@example.com",
            "x@example.com",
            "firstname.lastname@example.com",
            "email@subdomain.example.com",
            "firstname+lastname@example.com",
            "firstname-lastname@example.com",
            "1234567890@example.com",
            "_______@example.com",
            "example@s.solutions",
            "email@example-one.com",
            "example-indeed@strange-example.com",
            "email@example.name",
            "email@example.museum",
            "email@example.co.jp",
            "email@example.info",
            "email@example.org",
            "email@example.mil",
            "email@example.io",
            "email@example.to",
            "email@example.me",
    };
}