package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT.JWTparts;
import static org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT.decodeSection;
import static org.mockito.Mockito.when;

public abstract class CredentialIdTypeAbstractTestJWT<CitJWT extends CredentialIdTypeAbstractJWT> {
    public static final String EMAIL_DEVIN = "devin@example.com";
    public static final String SIMPLE_CLAIMS_EMAIL_PREFIX = "{ \"loggedInAs\": \"admin\", \"email\": \"";
    public static final String SIMPLE_CLAIMS_EMAIL_SUFFIX = "\", \"iat\": 1422779638 }";

    public static final String JSON_HEADER = "{ \"alg\": \"HS256\", \"typ\": \"JWT\" }";
    public static final String JSON_CLAIMS = SIMPLE_CLAIMS_EMAIL_PREFIX + EMAIL_DEVIN + SIMPLE_CLAIMS_EMAIL_SUFFIX;
    public static final String RAW_SIGNATURE = "The quick brown fox jumped over the lazy moon‼"; // any bytes... note non-ascii char
    public static final String RAW_4TH_SECTION = "No clue what goes in here";

    public static final String B64_SECTION_HEADER = encodeSection(JSON_HEADER);
    public static final String B64_SECTION_CLAIMS = encodeSection(JSON_CLAIMS);
    public static final String B64_SECTION_SIGNATURE = encodeSection(RAW_SIGNATURE);
    public static final String B64_SECTION_4TH_SECTION = encodeSection(RAW_4TH_SECTION);

    public static final String JWT2 = B64_SECTION_HEADER + "." + B64_SECTION_CLAIMS; // 1 dot

    public static final String JWT3 = JWT2 + "." + B64_SECTION_SIGNATURE; // 2 dots

    public static final String JWT4 = JWT3 + "." + B64_SECTION_4TH_SECTION; // 3 dots

    public static final String JWT = JWT3;

    public static final String AUTH_HEADER_VALUE_PREFIX_UC = "Bearer ";
    public static final String AUTH_HEADER_VALUE_PREFIX_LC = "bearer ";

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
        String header = decodeSection(B64_SECTION_HEADER, "header");
        String claims = decodeSection(B64_SECTION_CLAIMS, "claims");
        String signature = decodeSection(B64_SECTION_SIGNATURE, "signature");
        String fourth = decodeSection(B64_SECTION_4TH_SECTION, "fourth");

        assertThat(header).isEqualTo(JSON_HEADER);
        assertThat(claims).isEqualTo(JSON_CLAIMS);
        assertThat(signature).isEqualTo(RAW_SIGNATURE);
        assertThat(fourth).isEqualTo(RAW_4TH_SECTION);
    }

    @Test
    public void checkJwtParts() {
        assertThat(JWTparts.from((RequestInfo) null)).isNull();
        assertThat(JWTparts.from((String) null)).isNull();
        assertThat(JWTparts.from("!" + AUTH_HEADER_VALUE_PREFIX_UC + JWT)).as("Not 'Bearer '").isNull();
        assertThat(JWTparts.from(AUTH_HEADER_VALUE_PREFIX_UC + B64_SECTION_HEADER)).as("Only 1 section").isNull();
        assertThat(JWTparts.from(AUTH_HEADER_VALUE_PREFIX_UC + JWT2)).as("Only 2 sections").isNull();
        assertThat(JWTparts.from(AUTH_HEADER_VALUE_PREFIX_UC + JWT2 + " ." + B64_SECTION_SIGNATURE)).as("space next to dot").isNull();
        checkJwtParts(AUTH_HEADER_VALUE_PREFIX_UC);
        checkJwtParts(AUTH_HEADER_VALUE_PREFIX_LC);
    }

    private void checkJwtParts(String authHeaderValuePrefix) {
        JWTparts parts = JWTparts.from(authHeaderValuePrefix + JWT);
        assertThat(parts).as(authHeaderValuePrefix + "JWTparts").isNotNull();
        assertThat(parts.token).as(authHeaderValuePrefix + "JWTparts.token").isEqualTo(JWT);
        String[] sections = parts.parts;
        assertThat(sections).as("JWTparts.parts.sections")
                .as(authHeaderValuePrefix + "JWTparts.sections").hasSize(3)
                .containsExactly(B64_SECTION_HEADER, B64_SECTION_CLAIMS, B64_SECTION_SIGNATURE);
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
        assertThat(id).as("Id mis-match from sample").isEqualTo("|" + "marissa@test.org" + "|");

        when(requestInfo.getAuthorizationHeader()).thenReturn(AUTH_HEADER_VALUE_PREFIX_LC + JWT4);
        id = factory.mapAuthorizationToCredentialsID(requestInfo);
        assertThat(id).as("Id mis-match from default 3 dot JWT").isEqualTo("|" + EMAIL_DEVIN + "|");

        for (String email : SAMPLE_EMAILS) {
            String jwt = "bad." + encodeSection(SIMPLE_CLAIMS_EMAIL_PREFIX + email + SIMPLE_CLAIMS_EMAIL_SUFFIX) + ".bad-bad";
            when(requestInfo.getAuthorizationHeader()).thenReturn(AUTH_HEADER_VALUE_PREFIX_UC + jwt);
            id = factory.mapAuthorizationToCredentialsID(requestInfo);
            assertThat(id).isEqualTo("|" + email + "|");
            System.out.println(email + " -> " + jwt);
        }
    }

    protected void checkFlavor(String postKeyConfig, Class<?> credentialIdExtractorClass, String extractedCredential) {
        AuthorizationCredentialIdExtractor factory = credentialIdType.factory(postKeyConfig);

        assertThat(factory.getClass()).isSameAs(credentialIdExtractorClass);
        when(requestInfo.getAuthorizationHeader()).thenReturn(AUTH_HEADER_VALUE_PREFIX_UC + JWT);
        String id = factory.mapAuthorizationToCredentialsID(requestInfo);
        assertThat(id).as("Id mis-match from: " + postKeyConfig).isEqualTo(extractedCredential);
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