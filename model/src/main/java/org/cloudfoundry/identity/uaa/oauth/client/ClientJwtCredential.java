package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import tools.jackson.core.type.TypeReference;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Setter;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.WildcardPatternCache;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
@Data
// Validation and the sub/sub_pattern invariant are enforced in the constructor, so the fields
// must not be reassignable afterwards.
@Setter(AccessLevel.NONE)
public class ClientJwtCredential {

    /**
     * Upper bound on a subject pattern, well above any real world 'sub' claim. Bounds both the
     * cost of a match and the size of a cache entry.
     */
    @JsonIgnore
    static final int MAX_SUBJECT_PATTERN_LENGTH = 256;

    @JsonIgnore
    private static final int MAX_WILDCARDS = 5;

    @JsonProperty("sub")
    private String subject;
    @JsonProperty("iss")
    private String issuer;
    @JsonProperty("aud")
    private String audience;
    @JsonProperty("sub_pattern")
    private String subjectPattern;

    @JsonCreator
    public ClientJwtCredential(@JsonProperty("sub") String subject, @JsonProperty("iss") String issuer,
            @JsonProperty("aud") String audience, @JsonProperty("sub_pattern") String subjectPattern) {
        this.issuer = issuer;
        this.audience = audience;
        // Normalise a blank pattern away, so that isSubjectPattern, credKey and equals cannot
        // disagree about whether this credential carries one.
        String pattern = StringUtils.hasText(subjectPattern) ? subjectPattern : null;
        this.subjectPattern = pattern;
        // sub and sub_pattern are mutually exclusive, so a subject supplied alongside a pattern
        // is a conflict rather than something to overwrite.
        if (pattern != null && StringUtils.hasText(subject) && !pattern.equals(subject)) {
            throw new IllegalArgumentException("Invalid federated jwt credentials");
        }
        // A pattern is mirrored into the subject so that subject is never null, which credKey,
        // equals and delete all rely on, and so that a node which does not yet know the
        // sub_pattern field compares the pattern text literally and therefore fails closed.
        this.subject = pattern != null ? pattern : subject;
        if (!isValid()) {
            throw new IllegalArgumentException("Invalid federated jwt credentials");
        }
    }

    public ClientJwtCredential(String subject, String issuer, String audience) {
        this(subject, issuer, audience, null);
    }

    private boolean isValid() {
        if (!StringUtils.hasText(subject) || !StringUtils.hasText(issuer)) {
            return false;
        }
        return !StringUtils.hasText(subjectPattern) || isValidSubjectPattern(subjectPattern);
    }

    private static boolean isValidSubjectPattern(String pattern) {
        if (pattern.length() > MAX_SUBJECT_PATTERN_LENGTH
                || pattern.indexOf('*') < 0
                || pattern.chars().filter(c -> c == '*').count() > MAX_WILDCARDS) {
            return false;
        }
        // A wildcard may stand in for a whole component, but the pattern as a whole has to pin
        // the structure around it. Requiring a component that is entirely literal rejects
        // patterns such as "*", "a*" or "*:*" that would authorise most of what the issuer can
        // assert, while still allowing the usual "prefix:*" and "prefix*" forms.
        if (Arrays.stream(pattern.split("[:/]", -1))
                .noneMatch(component -> component.indexOf('*') < 0
                        && component.chars().anyMatch(Character::isLetterOrDigit))) {
            return false;
        }
        try {
            subjectPatternOf(pattern);
        } catch (PatternSyntaxException e) {
            return false;
        }
        return true;
    }

    private static Pattern subjectPatternOf(String pattern) {
        return WildcardPatternCache.compile(pattern, UaaStringUtils::constructComponentWildcardPattern);
    }

    @JsonIgnore
    public boolean isSubjectPattern() {
        return StringUtils.hasText(subjectPattern);
    }

    /**
     * Whether the asserted subject is authorised by this credential. An exact credential must
     * match verbatim; a pattern credential matches when the whole subject matches the pattern,
     * where '*' stands for one component of the subject and '**' for a run of components
     * separated by '/'. Neither crosses the ':' claim separator.
     */
    public boolean matchesSubject(String assertedSubject) {
        if (assertedSubject == null) {
            return false;
        }
        if (!isSubjectPattern()) {
            return subject.equals(assertedSubject);
        }
        return assertedSubject.length() <= MAX_SUBJECT_PATTERN_LENGTH
                && subjectPatternOf(subjectPattern).matcher(assertedSubject).matches();
    }

    public static List<ClientJwtCredential> parse(String clientJwtCredentials) {
        try {
            return JsonUtils.readValue(clientJwtCredentials, new TypeReference<>() {});
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalArgumentException("Client jwt configuration cannot be parsed", e);
        }
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        ClientJwtCredential that = (ClientJwtCredential) object;
        return subject.equals(that.subject) &&
               issuer.equals(that.issuer) &&
               Objects.equals(audience, that.audience) &&
               Objects.equals(subjectPattern, that.subjectPattern);
    }

    @Override
    public int hashCode() {
        int result = subject.hashCode();
        result = 31 * result + issuer.hashCode();
        result = 31 * result + (audience != null ? audience.hashCode() : 0);
        result = 31 * result + (subjectPattern != null ? subjectPattern.hashCode() : 0);
        return result;
    }
}
