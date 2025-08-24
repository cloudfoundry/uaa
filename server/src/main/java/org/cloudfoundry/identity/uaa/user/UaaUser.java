package org.cloudfoundry.identity.uaa.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;
import org.cloudfoundry.identity.uaa.authentication.NonStringPassword;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * User data for authentication against UAA's internal authentication provider.
 *
 * @author Luke Taylor
 * @author Dave Syer
 * @author Joel D'sa
 */
@Getter
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UaaUser {
    static final String DEFAULT_EMAIL_DOMAIN = "this-default-was-not-configured.invalid";
    static final String DEFAULT_USER_NAME = "unknown";

    public static String emailFrom(String name) {
        String email = name;

        if (name.split("@").length != 2 || name.startsWith("@") || name.endsWith("@")) {
            email = name.replaceAll("@", "") + "@" + DEFAULT_EMAIL_DOMAIN;
        }

        return email;
    }

    public static UaaUser createWithDefaults(Consumer<UaaUserPrototype> config) {
        UaaUserPrototype prototype = new UaaUserPrototype();
        config.accept(prototype);

        if (prototype.getUsername() == null) {
            prototype.withUsername(prototype.getEmail() != null ? prototype.getEmail() : DEFAULT_USER_NAME);
        }

        if (prototype.getEmail() == null) {
            prototype.withEmail(emailFrom(prototype.getUsername()));
        }

        if (prototype.getGivenName() == null) {
            prototype.withGivenName(prototype.getEmail().split("@")[0]);
        }

        if (prototype.getFamilyName() == null) {
            String email = prototype.getEmail();
            String familyName = email.split("@").length > 1 ? email.split("@")[1] : email;
            prototype.withFamilyName(familyName);
        }

        if (prototype.getCreated() == null) {
            prototype.withCreated(new Date());
        }

        if (prototype.getModified() == null) {
            prototype.withModified(prototype.getCreated());
        }

        return new UaaUser(prototype);
    }

    private final String id;

    private final String username;

    private final NonStringPassword password;

    private final String email;

    private final String givenName;

    private final String familyName;

    private final Date created;

    private final Date modified;

    private final String origin;

    private final String externalId;

    private final String salt;

    private final Date passwordLastModified;

    private final String phoneNumber;

    @Setter
    private Long lastLogonTime;

    @Setter
    private Long previousLogonTime;

    private final String zoneId;

    private final List<? extends GrantedAuthority> authorities;

    @Setter
    private boolean verified;

    private boolean legacyVerificationBehavior;

    @Setter
    private boolean passwordChangeRequired;

    public UaaUser(String username, String password, String email, String givenName, String familyName) {
        this("NaN", username, password, email, UaaAuthority.USER_AUTHORITIES, givenName, familyName, new Date(),
                new Date(), null, null, false, null, null, new Date());
    }

    public UaaUser(String username, String password, String email, String givenName, String familyName, String origin, String zoneId) {
        this("NaN", username, password, email, UaaAuthority.USER_AUTHORITIES, givenName, familyName, new Date(),
                new Date(), origin, null, false, zoneId, null, new Date());
    }

    public UaaUser(String id, String username, String password, String email,
            List<? extends GrantedAuthority> authorities,
            String givenName, String familyName, Date created, Date modified,
            String origin, String externalId, boolean verified, String zoneId, String salt,
            Date passwordLastModified) {
        this(new UaaUserPrototype()
                .withId(id)
                .withUsername(username)
                .withPassword(password)
                .withEmail(email)
                .withFamilyName(familyName)
                .withGivenName(givenName)
                .withCreated(created)
                .withModified(modified)
                .withAuthorities(authorities)
                .withOrigin(origin)
                .withExternalId(externalId)
                .withVerified(verified)
                .withZoneId(zoneId)
                .withSalt(salt)
                .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser(UaaUserPrototype prototype) {
        Assert.hasText(prototype.getId(), "Id cannot be null");
        Assert.hasText(prototype.getUsername(), "Username cannot be empty");
        Assert.hasText(prototype.getEmail(), "Email is required");

        this.id = prototype.getId();
        this.username = prototype.getUsername();
        this.password = prototype.getNonStringPassword();
        this.email = prototype.getEmail();
        this.familyName = prototype.getFamilyName();
        this.givenName = prototype.getGivenName();
        this.created = prototype.getCreated();
        this.modified = prototype.getModified();
        this.authorities = prototype.getAuthorities();
        this.origin = prototype.getOrigin();
        this.externalId = prototype.getExternalId();
        this.verified = prototype.isVerified();
        this.zoneId = prototype.getZoneId();
        this.salt = prototype.getSalt();
        this.passwordLastModified = prototype.getPasswordLastModified();
        this.phoneNumber = prototype.getPhoneNumber();
        this.legacyVerificationBehavior = prototype.isLegacyVerificationBehavior();
        this.passwordChangeRequired = prototype.isPasswordChangeRequired();
        this.lastLogonTime = prototype.getLastLogonTime();
        this.previousLogonTime = prototype.getPreviousLogonTime();
    }

    public String getPassword() {
        return password.getPassword();
    }

    public List<? extends GrantedAuthority> getAuthorities() {
        return Optional.ofNullable(authorities).orElseThrow();
    }

    public UaaUser id(String id) {
        if (!"NaN".equals(this.id)) {
            throw new IllegalStateException("Id already set");
        }
        return new UaaUser(id, username, getPassword(), email, authorities, givenName, familyName, created, modified, origin, externalId, verified, zoneId, salt, passwordLastModified);
    }

    public UaaUser authorities(Collection<? extends GrantedAuthority> authorities) {
        ArrayList<GrantedAuthority> values = new ArrayList<>(authorities);
        for (int i = 0; i < values.size(); i++) {
            GrantedAuthority authority = values.get(i);
            values.set(i, UaaAuthority.authority(authority.toString()));
        }
        if (!values.contains(UaaAuthority.UAA_USER)) {
            values.add(UaaAuthority.UAA_USER);
        }
        return new UaaUser(new UaaUserPrototype(this).withAuthorities(values));
    }

    @Override
    public String toString() {
        return "[UaaUser {id=" + id + ", username=" + username + ", email=" + email + ", givenName=" + givenName
                + ", familyName=" + familyName + "}]";
    }

    public UaaUser modifySource(String origin, String externalId) {
        return new UaaUser(
                new UaaUserPrototype()
                        .withEmail(email)
                        .withGivenName(givenName)
                        .withFamilyName(familyName)
                        .withPhoneNumber(phoneNumber)
                        .withModified(modified)
                        .withId(id)
                        .withUsername(username)
                        .withPassword(password)
                        .withAuthorities(authorities)
                        .withCreated(created)
                        .withOrigin(origin)
                        .withExternalId(externalId)
                        .withVerified(verified)
                        .withZoneId(zoneId)
                        .withSalt(salt)
                        .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser modifyEmail(String email) {
        return new UaaUser(
                new UaaUserPrototype()
                        .withEmail(email)
                        .withGivenName(givenName)
                        .withFamilyName(familyName)
                        .withPhoneNumber(phoneNumber)
                        .withModified(modified)
                        .withId(id)
                        .withUsername(username)
                        .withPassword(password)
                        .withAuthorities(authorities)
                        .withCreated(created)
                        .withOrigin(origin)
                        .withExternalId(externalId)
                        .withVerified(verified)
                        .withZoneId(zoneId)
                        .withSalt(salt)
                        .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser modifyOrigin(String origin) {
        return new UaaUser(
                new UaaUserPrototype()
                        .withEmail(email)
                        .withGivenName(givenName)
                        .withFamilyName(familyName)
                        .withPhoneNumber(phoneNumber)
                        .withModified(modified)
                        .withId(id)
                        .withUsername(username)
                        .withPassword(password)
                        .withAuthorities(authorities)
                        .withCreated(created)
                        .withOrigin(origin)
                        .withExternalId(externalId)
                        .withVerified(verified)
                        .withZoneId(zoneId)
                        .withSalt(salt)
                        .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser modifyId(String id) {
        return new UaaUser(
                new UaaUserPrototype()
                        .withEmail(email)
                        .withGivenName(givenName)
                        .withFamilyName(familyName)
                        .withPhoneNumber(phoneNumber)
                        .withModified(modified)
                        .withId(id)
                        .withUsername(username)
                        .withPassword(password)
                        .withAuthorities(authorities)
                        .withCreated(created)
                        .withOrigin(origin)
                        .withExternalId(externalId)
                        .withVerified(verified)
                        .withZoneId(zoneId)
                        .withSalt(salt)
                        .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser modifyUsername(String username) {
        return new UaaUser(
                new UaaUserPrototype()
                        .withEmail(email)
                        .withGivenName(givenName)
                        .withFamilyName(familyName)
                        .withPhoneNumber(phoneNumber)
                        .withModified(modified)
                        .withId(id)
                        .withUsername(username)
                        .withPassword(password)
                        .withAuthorities(authorities)
                        .withCreated(created)
                        .withOrigin(origin)
                        .withExternalId(externalId)
                        .withVerified(verified)
                        .withZoneId(zoneId)
                        .withSalt(salt)
                        .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser modifyAttributes(String email,
            String givenName,
            String familyName,
            String phoneNumber,
            String externalId,
            boolean verified) {
        return new UaaUser(new UaaUserPrototype()
                .withEmail(email)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withPhoneNumber(phoneNumber)
                .withModified(modified)
                .withId(id)
                .withUsername(username)
                .withPassword(password)
                .withAuthorities(authorities)
                .withCreated(created)
                .withOrigin(origin)
                .withExternalId(externalId)
                .withVerified(verified)
                .withZoneId(zoneId)
                .withSalt(salt)
                .withPasswordLastModified(passwordLastModified));
    }
}
