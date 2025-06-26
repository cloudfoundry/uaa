/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Group;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.fail;

/**
 * @author Luke Taylor
 */
class ScimUserTests {

    private static final String SCHEMAS = "\"schemas\": [\"urn:scim:schemas:core:1.0\"],";
    private ScimUser user;
    private ScimUser patch;

    @BeforeEach
    void createUserToBePatched() {
        user = new ScimUser("id", "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        user.addPhoneNumber("0123456789");
        user.getName().setHonorificSuffix("suffix");
        user.getName().setHonorificPrefix("prefix");
        user.getName().setMiddleName("middle");
        user.setDisplayName("display");
        user.setNickName("nick");
        user.setTimezone("America/Denver");
        user.setTitle("title");
        user.setProfileUrl("profile_url");
        user.setLocale("en.UTF-8");
        user.setPreferredLanguage("en");

        patch = new ScimUser();
    }

    @Test
    void serializeNullPhoneNumber() {
        ScimUser user = new ScimUser("id", "username", "giveName", "familyName");
        String json = JsonUtils.writeValueAsString(user);
        ScimUser user1 = JsonUtils.readValue(json, ScimUser.class);
        assertThat(user1.getPhoneNumbers()).isNull();

        user.setPhoneNumbers(null);
        json = JsonUtils.writeValueAsString(user);
        user1 = JsonUtils.readValue(json, ScimUser.class);
        assertThat(user1.getPhoneNumbers()).isNull();

        json = json.replace("\"id\":\"id\"", "\"id\":\"id\", \"phoneNumbers\":[]");
        user1 = JsonUtils.readValue(json, ScimUser.class);
        assertThat(user1.getPhoneNumbers()).isNotNull();

        json = json.replace("\"phoneNumbers\":[]", "\"phoneNumbers\":null");
        user1 = JsonUtils.readValue(json, ScimUser.class);
        assertThat(user1.getPhoneNumbers()).isNotNull();
    }

    @Test
    void logon_timestamps_are_null() {
        String oldJson = "{\"id\":\"78df8903-58e9-4a1e-8e22-b0421f7d6d70\",\"meta\":{\"version\":0,\"created\":\"2015-08-21T15:09:26.830Z\",\"lastModified\":\"2015-08-21T15:09:26.830Z\"},\"userName\":\"jo!!!@foo.com\",\"name\":{\"familyName\":\"User\",\"givenName\":\"Jo\"},\"emails\":[{\"value\":\"jo!!!@foo.com\",\"primary\":false}],\"active\":true,\"verified\":false,\"origin\":\"uaa\",\"zoneId\":\"uaa\",\"passwordLastModified\":null,\"schemas\":[\"urn:scim:schemas:core:1.0\"]}";
        for (String json : Arrays.asList(oldJson, JsonUtils.writeValueAsString(new ScimUser()))) {
            ScimUser user = JsonUtils.readValue(json, ScimUser.class);
            assertThat(user.getPreviousLogonTime()).as(json).isNull();
            assertThat(user.getLastLogonTime()).as(json).isNull();
        }
    }

    @Test
    void deserializeNullPasswordLastModified() {
        String json = "{\"id\":\"78df8903-58e9-4a1e-8e22-b0421f7d6d70\",\"meta\":{\"version\":0,\"created\":\"2015-08-21T15:09:26.830Z\",\"lastModified\":\"2015-08-21T15:09:26.830Z\"},\"userName\":\"jo!!!@foo.com\",\"name\":{\"familyName\":\"User\",\"givenName\":\"Jo\"},\"emails\":[{\"value\":\"jo!!!@foo.com\",\"primary\":false}],\"active\":true,\"verified\":false,\"origin\":\"uaa\",\"zoneId\":\"uaa\",\"passwordLastModified\":null,\"schemas\":[\"urn:scim:schemas:core:1.0\"]}";
        JsonUtils.readValue(json, ScimUser.class);
    }

    @Test
    void minimalJsonMapsToUser() {
        String minimal = "{" + SCHEMAS +
                "  \"userName\": \"bjensen@example.com\"\n" +
                "}";

        ScimUser user = JsonUtils.readValue(minimal, ScimUser.class);
        assertThat(user.getUserName()).isEqualTo("bjensen@example.com");
        assertThat(user.getPassword()).isNull();
    }

    @Test
    void passwordJsonMapsToUser() {
        String minimal = "{" + SCHEMAS +
                "  \"userName\": \"bjensen@example.com\",\n" +
                "  \"password\": \"foo\"\n" +
                "}";

        ScimUser user = JsonUtils.readValue(minimal, ScimUser.class);
        assertThat(user.getPassword()).isEqualTo("foo");
    }

    @Test
    void minimalUserMapsToJson() throws Exception {
        ScimUser user = new ScimUser();
        user.setId("123");
        user.setUserName("joe");
        user.getMeta().setCreated(new SimpleDateFormat("yyyy-MM-dd").parse("2011-11-30"));

        String json = JsonUtils.writeValueAsString(user);
        assertThat(json).contains("\"userName\":\"joe\"")
                .contains("\"id\":\"123\"")
                .contains("\"meta\":")
                .contains("\"created\":\"2011-11-30")
                .matches(".*\\\"created\\\":\\\"([0-9-]*-?)T([0-9:.]*)Z\\\".*")
                .doesNotContain("\"lastModified\":");
    }

    @Test
    void anotherUserMapsToJson() throws Exception {
        ScimUser user = new ScimUser();
        user.setId("123");
        user.setUserName("joe");
        user.getMeta().setCreated(new SimpleDateFormat("yyyy-MM-dd").parse("2011-11-30"));
        user.addEmail("joe@test.org");
        user.addPhoneNumber("+1-222-1234567");

        String json = JsonUtils.writeValueAsString(user);
        assertThat(json).contains("\"emails\":")
                .contains("\"phoneNumbers\":");
    }

    @Test
    void userWithGroupsMapsToJson() {
        ScimUser user = new ScimUser();
        user.setId("123");
        user.setUserName("joe");
        user.setGroups(Collections.singleton(new Group(null, "foo")));

        String json = JsonUtils.writeValueAsString(user);
        assertThat(json).contains("\"groups\":");
    }

    @Test
    void emailsAreMappedCorrectly() {
        String json = """
                { "userName":"bjensen",\
                "emails": [
                {"value": "bj@jensen.org","type": "other"},\
                {"value": "bjensen@example.com", "type": "work","primary": true},\
                {"value": "babs@jensen.org","type": "home"}\
                ],
                "schemas":["urn:scim:schemas:core:1.0"]}\
                """;
        ScimUser user = JsonUtils.readValue(json, ScimUser.class);
        assertThat(user.getEmails()).hasSize(3);
        assertThat(user.getEmails().get(1).getValue()).isEqualTo("bjensen@example.com");
        assertThat(user.getEmails().get(2).getValue()).isEqualTo("babs@jensen.org");
        assertThat(user.getPrimaryEmail()).isEqualTo("bjensen@example.com");
        assertThat(user.getEmails().getFirst().isPrimary()).isFalse();
    }

    @Test
    void groupsAreMappedCorrectly() {
        String json = """
                { "userName":"bjensen",\
                "groups": [
                {"value": "12345","display": "uaa.admin"},\
                {"value": "123456","display": "dash.admin"}\
                ],
                "schemas":["urn:scim:schemas:core:1.0"]}\
                """;
        ScimUser user = JsonUtils.readValue(json, ScimUser.class);
        assertThat(user.getGroups()).hasSize(2);
    }

    @Test
    void datesAreMappedCorrectly() {
        String json = "{ \"userName\":\"bjensen\"," +
                "\"meta\":{\"version\":10,\"created\":\"2011-11-30T10:46:16.475Z\"}}";
        ScimUser user = JsonUtils.readValue(json, ScimUser.class);
        assertThat(user.getVersion()).isEqualTo(10);
        assertThat(new SimpleDateFormat("yyyy-MM-dd").format(user.getMeta().getCreated())).isEqualTo("2011-11-30");
    }

    @Test
    void basicNamesAreMappedCorrectly() {
        ScimUser roz = new ScimUser("1234", "roz", "Roslyn", "MacRae");
        assertThat(roz.getId()).isEqualTo("1234");
        assertThat(roz.getUserName()).isEqualTo("roz");
        assertThat(roz.getGivenName()).isEqualTo("Roslyn");
        assertThat(roz.getFamilyName()).isEqualTo("MacRae");
        roz.setId("12345");
        assertThat(roz.getId()).isEqualTo("12345");
        assertThat(roz.getUserName()).isEqualTo("roz");
        assertThat(roz.getGivenName()).isEqualTo("Roslyn");
        assertThat(roz.getFamilyName()).isEqualTo("MacRae");
        roz.setUserName("roz1");
        assertThat(roz.getId()).isEqualTo("12345");
        assertThat(roz.getUserName()).isEqualTo("roz1");
        assertThat(roz.getGivenName()).isEqualTo("Roslyn");
        assertThat(roz.getFamilyName()).isEqualTo("MacRae");
        ScimUser.Name name = new ScimUser.Name("Roslyn", "MacRae");
        roz.setName(name);
        assertThat(roz.getName()).isSameAs(name);
        assertThat(roz.getApprovals()).isNull();
        Set<Approval> approvals = new HashSet<>();
        roz.setApprovals(approvals);
        assertThat(roz.getApprovals()).isSameAs(approvals);
        List<ScimUser.PhoneNumber> phoneNumbers = new LinkedList<>();
        ScimUser.PhoneNumber p1 = new ScimUser.PhoneNumber();
        phoneNumbers.add(p1);
        roz.setPhoneNumbers(phoneNumbers);
        assertThat(roz.getPhoneNumbers()).isEmpty();
        p1.setValue("value");
        p1.setType("type");
        roz.setPhoneNumbers(phoneNumbers);
        assertThat(roz.getPhoneNumbers()).hasSize(1);

        assertThat(roz.getDisplayName()).isNull();
        roz.setDisplayName("DisplayName");
        assertThat(roz.getDisplayName()).isEqualTo("DisplayName");

        assertThat(roz.getProfileUrl()).isNull();
        roz.setProfileUrl("ProfileUrl");
        assertThat(roz.getProfileUrl()).isEqualTo("ProfileUrl");

        assertThat(roz.getTitle()).isNull();
        roz.setTitle("Title");
        assertThat(roz.getTitle()).isEqualTo("Title");

        assertThat(roz.getUserType()).isNull();
        roz.setUserType("UserType");
        assertThat(roz.getUserType()).isEqualTo("UserType");

        assertThat(roz.getPreferredLanguage()).isNull();
        roz.setPreferredLanguage("PreferredLanguage");
        assertThat(roz.getPreferredLanguage()).isEqualTo("PreferredLanguage");

        assertThat(roz.getLocale()).isNull();
        roz.setLocale("Locale");
        assertThat(roz.getLocale()).isEqualTo("Locale");

        assertThat(roz.isActive()).isTrue();
        roz.setActive(false);
        assertThat(roz.isActive()).isFalse();

        assertThat(roz.getTimezone()).isNull();
        roz.setTimezone("Timezone");
        assertThat(roz.getTimezone()).isEqualTo("Timezone");

        assertThat(roz.getOrigin()).isEmpty();
        roz.setOrigin("Origin");
        assertThat(roz.getOrigin()).isEqualTo("Origin");

        assertThat(roz.getExternalId()).isEmpty();
        roz.setExternalId("ExternalId");
        assertThat(roz.getExternalId()).isEqualTo("ExternalId");

        assertThat(roz.getNickName()).isNull();
        roz.setNickName("NickName");
        assertThat(roz.getNickName()).isEqualTo("NickName");

        assertThat(roz.isVerified()).isTrue();
        roz.setVerified(false);
        assertThat(roz.isVerified()).isFalse();
    }

    @Test
    void spelFilter() {
        ScimUser user = new ScimUser();
        user.setId("123");
        user.setUserName("joe");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("foo@bar.com");
        user.setEmails(Collections.singletonList(email));
        StandardEvaluationContext context = new StandardEvaluationContext(user);
        assertThat(new SpelExpressionParser().parseExpression(
                "userName == 'joe' and !(emails.?[value=='foo@bar.com']).empty").getValue(context,
                Boolean.class)).isTrue();
    }

    @Test
    void setPrimaryEmail() {
        ScimUser user = new ScimUser();

        assertThat(user.getPrimaryEmail()).isNull();
        user.setPrimaryEmail("email0@bar.com");
        assertThat(user.getPrimaryEmail()).isEqualTo("email0@bar.com");

        ScimUser.Email email1 = new ScimUser.Email();
        email1.setValue("email1@bar.com");
        user.setEmails(new LinkedList<>(Collections.singletonList(email1)));
        assertThat(user.getPrimaryEmail()).isEqualTo("email1@bar.com");

        email1.setPrimary(true);
        ScimUser.Email email2 = new ScimUser.Email();
        email2.setValue("email2@bar.com");
        ScimUser.Email email3 = new ScimUser.Email();
        email3.setValue("email3@bar.com");
        user.setEmails(Arrays.asList(email1, email2, email3));

        ScimUser.Email newEmail = new ScimUser.Email();
        newEmail.setValue("new@example.com");
        newEmail.setPrimary(true);

        user.setPrimaryEmail(newEmail.getValue());

        assertThat(user.getPrimaryEmail()).isEqualTo("new@example.com");

        assertThat(user.getEmails()).isEqualTo(Arrays.asList(newEmail, email2, email3));

        try {
            user.addEmail("email3@bar.com");
            fail("");
        } catch (IllegalArgumentException x) {
            assertThat(x.getMessage()).isEqualTo("Already contains email email3@bar.com");
        }
        user.setUserName("userName");
        user.setNickName("nickName");
        user.setName(new ScimUser.Name("givenName", "familyName"));
        assertThat(user.wordList()).hasSize(7);
    }

    @Test
    void groupSettersGetters() {
        Group group = new Group("id", "display", Group.Type.DIRECT);
        group.setType(Group.Type.DIRECT);
        assertThat(group.getType()).isEqualTo(Group.Type.DIRECT);
        group.setType(Group.Type.INDIRECT);
        assertThat(group.getType()).isEqualTo(Group.Type.INDIRECT);
        group.setType(null);
        assertThat(group.getType()).isNull();

        Group group1 = new Group("id", "display", Group.Type.DIRECT);
        Group group2 = new Group("id", "display", Group.Type.DIRECT);
        assertThat(group2).isEqualTo(group1);
        assertThat(group1)
                .isEqualTo(group2);
        assertThat(new Object()).isNotEqualTo(group1);
        group1.setValue(null);
        assertThat(group2).isNotEqualTo(group1);
        assertThat(group1).isNotEqualTo(group2);
        group2.setValue(null);
        assertThat(group2).isEqualTo(group1);
        group1.setDisplay(null);
        assertThat(group2).isNotEqualTo(group1);
        assertThat(group1).isNotEqualTo(group2);
        group2.setDisplay(null);
        assertThat(group2).isEqualTo(group1);
        assertThat(group2.toString()).isNotNull();
    }

    @Test
    void name() {
        ScimUser.Name name1 = new ScimUser.Name();
        assertThat(name1.getFamilyName()).isNull();
        assertThat(name1.getFormatted()).isNull();
        assertThat(name1.getGivenName()).isNull();
        assertThat(name1.getHonorificPrefix()).isNull();
        assertThat(name1.getHonorificSuffix()).isNull();
        assertThat(name1.getMiddleName()).isNull();

        name1.setFamilyName("familyName");
        assertThat(name1.getFamilyName()).isEqualTo("familyName");
        name1.setGivenName("givenName");
        assertThat(name1.getGivenName()).isEqualTo("givenName");
        assertThat(name1.getFormatted()).isNull();
        name1.setHonorificPrefix("honorificPrefix");
        assertThat(name1.getHonorificPrefix()).isEqualTo("honorificPrefix");
        name1.setHonorificSuffix("honorificSuffix");
        assertThat(name1.getHonorificSuffix()).isEqualTo("honorificSuffix");
        name1.setFormatted("formatted");
        assertThat(name1.getFormatted()).isEqualTo("formatted");
        name1.setMiddleName("middle");
        assertThat(name1.getMiddleName()).isEqualTo("middle");
        ScimUser.Name name2 = new ScimUser.Name("givenName", "familyName");
        assertThat(name2.getFormatted()).isEqualTo("givenName familyName");
    }

    @Test
    void email() {
        ScimUser.Email email1 = new ScimUser.Email();
        ScimUser.Email email2 = new ScimUser.Email();
        assertThat(email2).isEqualTo(email1);
        assertThat(email1).isEqualTo(email2);
        assertThat(email2).hasSameHashCodeAs(email1);
        email1.setPrimary(true);
        assertThat(email2).isNotEqualTo(email1);
        assertThat(email1).isNotEqualTo(email2);
        email2.setPrimary(true);
        assertThat(email2).isEqualTo(email1);
        assertThat(email1).isEqualTo(email2);
        assertThat(email2).hasSameHashCodeAs(email1);
        email1.setType("work");
        assertThat(email2).isNotEqualTo(email1);
        assertThat(email1).isNotEqualTo(email2);
        email2.setType("home");
        assertThat(email2).isNotEqualTo(email1);
        assertThat(email1).isNotEqualTo(email2);
        email2.setType("work");
        assertThat(email2).isEqualTo(email1);
        assertThat(email1).isEqualTo(email2);
        assertThat(email2).hasSameHashCodeAs(email1);
        email1.setValue("value@value.org");
        assertThat(email2).isNotEqualTo(email1);
        assertThat(email1).isNotEqualTo(email2);
        email2.setValue("value@value.org");
        assertThat(email2).isEqualTo(email1);
        assertThat(email1).isEqualTo(email2);
        assertThat(email2).hasSameHashCodeAs(email1);
    }

    @Test
    void phoneNumber() {
        ScimUser.PhoneNumber p1 = new ScimUser.PhoneNumber();
        assertThat(p1.getType()).isNull();
        assertThat(p1.getValue()).isNull();
        p1.setValue("value");
        p1.setType("type");
        assertThat(p1.getValue()).isEqualTo("value");
        assertThat(p1.getType()).isEqualTo("type");
        ScimUser user = new ScimUser();
        user.setPhoneNumbers(Collections.singletonList(p1));

        // should reject adding duplicate phone number if the existing has a type set to null
        p1.setType(null);
        assertThatIllegalArgumentException()
                .isThrownBy(() -> user.addPhoneNumber(p1.getValue()))
                .withMessageStartingWith("Already contains phoneNumber");
    }

    @Test
    void passwordLastModified() {
        ScimUser user = new ScimUser();
        assertThat(user.getPasswordLastModified()).isNull();
        user.setId("someid");
        assertThat(user.getPasswordLastModified()).isSameAs(user.getMeta().getCreated());

        Date d = new Date(System.currentTimeMillis());
        user.setPasswordLastModified(d);
        assertThat(user.getPasswordLastModified()).isSameAs(d);
    }

    @Test
    void user_verified_byDefault() {
        ScimUser user = new ScimUser();
        assertThat(user.isVerified()).isTrue();
    }

    @Test
    void patch_last_logon() {
        patch.setLastLogonTime(System.currentTimeMillis());
        user.patch(patch);
        assertThat(user.getLastLogonTime()).isNull();
    }

    @Test
    void patch_previous_logon() {
        patch.setPreviousLogonTime(System.currentTimeMillis());
        user.patch(patch);
        assertThat(user.getPreviousLogonTime()).isNull();
    }

    @Test
    void patchAliasId() {
        final String aliasId = UUID.randomUUID().toString();
        patch.setAliasId(aliasId);
        user.patch(patch);
        assertThat(user.getAliasId()).isEqualTo(aliasId);
    }

    @Test
    void patchAliasZid() {
        final String aliasZid = UUID.randomUUID().toString();
        patch.setAliasZid(aliasZid);
        user.patch(patch);
        assertThat(user.getAliasZid()).isEqualTo(aliasZid);
    }

    @Test
    void aliasPropertiesGettersAndSetters() {
        final String aliasId = UUID.randomUUID().toString();
        final String aliasZid = UUID.randomUUID().toString();

        final ScimUser scimUser = new ScimUser("id", "uname", "gname", "fname");
        scimUser.setAliasId(aliasId);
        scimUser.setAliasZid(aliasZid);
        assertThat(scimUser.getAliasId()).isEqualTo(aliasId);
        assertThat(scimUser.getAliasZid()).isEqualTo(aliasZid);
    }

    @Test
    void patchUserSetPrimaryEmail() {
        ScimUser.Email newMail = new ScimUser.Email();
        newMail.setPrimary(true);
        newMail.setValue("newTest@example.org");
        patch.setEmails(Collections.singletonList(newMail));
        user.patch(patch);
        assertThat(user.getPrimaryEmail()).isEqualTo("newTest@example.org");
    }

    @Test
    void patchUserSelectPrimaryEmailFromList() {
        ScimUser.Email newMail = new ScimUser.Email();
        newMail.setPrimary(false);
        newMail.setValue("newTest@example.org");
        ScimUser.Email secondMail = new ScimUser.Email();
        newMail.setPrimary(true);
        newMail.setValue("secondTest@example.org");
        patch.setEmails(Arrays.asList(newMail, secondMail));
        user.patch(patch);
        assertThat(user.getPrimaryEmail()).isEqualTo("secondTest@example.org");
        //complex property is merged. not replaced.
        assertThat(user.getEmails()).hasSize(3);

        //drop the email first
        patch.getMeta().setAttributes(new String[]{"emails"});
        user.patch(patch);
        assertThat(user.getPrimaryEmail()).isEqualTo("secondTest@example.org");
        assertThat(user.getEmails()).hasSize(2);
    }

    @Test
    void patchUserChangeUserName() {
        patch.setUserName("newUsername");
        user.patch(patch);
        assertThat(user.getUserName()).isEqualTo("newUsername");

        //username is a required field
        patch.getMeta().setAttributes(new String[]{"username"});
        patch.setUserName(null);
        try {
            user.patch(patch);
            fail("username is a required field, can't nullify it.");
        } catch (IllegalArgumentException ignored) {
            // ignore
        }
        assertThat(user.getUserName()).isNotNull();

        //we can drop and set the username again
        patch.setUserName("newUsername2");
        user.patch(patch);
        assertThat(user.getUserName()).isEqualTo("newUsername2");
    }

    @Test
    void patchUserChangeName() {
        patch.setName(new ScimUser.Name("Test", "Name"));
        user.patch(patch);
        assertThat(user.getName().getGivenName()).isEqualTo("Test");
        assertThat(user.getName().getFamilyName()).isEqualTo("Name");
    }

    @Test
    void patchUserDropName() {
        patch.setName(new ScimUser.Name("given-only", null));
        user.patch(patch);
        assertThat(user.getName().getGivenName()).isEqualTo("given-only");
        assertThat(user.getName().getFamilyName()).isNotNull();

        patch.getMeta().setAttributes(new String[]{"NAME"});
        user.patch(patch);
        assertThat(user.getName().getGivenName()).isEqualTo("given-only");
        assertThat(user.getName().getFamilyName()).isNull();
    }

    @Test
    void patchUserDropNameSubAttributes() {
        patch.setName(null);
        patch.getMeta().setAttributes(new String[]{"name.givenname"});
        user.patch(patch);
        assertThat(user.getName().getGivenName()).isNull();
        assertThat(user.getName().getFamilyName()).isNotNull();

        patch.getMeta().setAttributes(new String[]{"Name.familyname"});
        user.patch(patch);
        assertThat(user.getName().getGivenName()).isNull();
        assertThat(user.getName().getFamilyName()).isNull();
    }

    @Test
    void patchUserRejectChangingOrigin() {
        patch.setOrigin("some-new-origin");
        assertThatIllegalArgumentException().isThrownBy(() -> user.patch(patch))
                .withMessage("Cannot change origin in patch of user.");
    }

    @Test
    void patchUserDropNonUsedAttributes() {
        int pos = 0;
        allSet(pos++);
        setAndPatchAndValidate("displayname", pos++);
        setAndPatchAndValidate("nickname", pos++);
        setAndPatchAndValidate("profileurl", pos++);
        setAndPatchAndValidate("title", pos++);
        setAndPatchAndValidate("locale", pos++);
        setAndPatchAndValidate("timezone", pos++);
        setAndPatchAndValidate("name.honorificprefix", pos++);
        setAndPatchAndValidate("name.honorificsuffix", pos++);
        setAndPatchAndValidate("name.formatted", pos++);
        setAndPatchAndValidate("name.middlename", pos++);
        setAndPatchAndValidate("name.givenname", pos++);
        setAndPatchAndValidate("name.familyname", pos++);
        setAndPatchAndValidate("preferredlanguage", pos++);

        pos--;
        patch.setName(new ScimUser.Name(null, null));
        patch.getName().setFormatted(null);

        patch.setPreferredLanguage("test");
        setAndPatchAndValidate("preferredlanguage", --pos);

        patch.getName().setFamilyName("test");
        setAndPatchAndValidate("name.familyname", --pos);

        patch.getName().setGivenName("test");
        setAndPatchAndValidate("name.givenname", --pos);

        patch.getName().setMiddleName("test");
        setAndPatchAndValidate("name.middlename", --pos);

        patch.getName().setFormatted("test");
        setAndPatchAndValidate("name.formatted", --pos);

        patch.getName().setHonorificSuffix("test");
        setAndPatchAndValidate("name.honorificsuffix", --pos);

        patch.getName().setHonorificPrefix("test");
        setAndPatchAndValidate("name.honorificprefix", --pos);

        patch.setTimezone("test");
        setAndPatchAndValidate("timezone", --pos);

        patch.setLocale("test");
        setAndPatchAndValidate("locale", --pos);

        patch.setTitle("test");
        setAndPatchAndValidate("title", --pos);

        patch.setProfileUrl("test");
        setAndPatchAndValidate("profileurl", --pos);

        patch.setNickName("test");
        setAndPatchAndValidate("nickname", --pos);

        patch.setDisplayName("test");
        setAndPatchAndValidate("displayname", --pos);

        assertThat(pos).isZero();
    }

    public void setAndPatchAndValidate(String attribute, int nullable) {
        patch.getMeta().setAttributes(new String[]{attribute});
        user.patch(patch);
        allSet(nullable);
    }

    public void doAssertNull(int skip, int pos, Object value) {
        if (skip <= pos) {
            assertThat(value).isNotNull();
        } else {
            assertThat(value).isNull();
        }
    }

    protected void allSet(int nullable) {
        int pos = 0;
        doAssertNull(nullable, pos++, user.getDisplayName());
        doAssertNull(nullable, pos++, user.getNickName());
        doAssertNull(nullable, pos++, user.getProfileUrl());
        doAssertNull(nullable, pos++, user.getTitle());
        doAssertNull(nullable, pos++, user.getLocale());
        doAssertNull(nullable, pos++, user.getTimezone());
        doAssertNull(nullable, pos++, user.getName().getHonorificPrefix());
        doAssertNull(nullable, pos++, user.getName().getHonorificSuffix());
        doAssertNull(nullable, pos++, user.getName().getFormatted());
        doAssertNull(nullable, pos++, user.getName().getMiddleName());
        doAssertNull(nullable, pos++, user.getName().getGivenName());
        doAssertNull(nullable, pos++, user.getName().getFamilyName());
        doAssertNull(nullable, pos++, user.getPreferredLanguage());
    }

    @Test
    void patchUserDropAndChangeName() {
        patch.getMeta().setAttributes(new String[]{"NAME"});
        user.patch(patch);
        assertThat(user.getName().getGivenName()).isNull();
        assertThat(user.getName().getFamilyName()).isNull();

        patch.setName(new ScimUser.Name("Test", "Name"));
        user.patch(patch);
        assertThat(user.getName().getGivenName()).isEqualTo("Test");
        assertThat(user.getName().getFamilyName()).isEqualTo("Name");
    }

    @Test
    void patchUserChangePhone() {
        ScimUser.PhoneNumber newNumber = new ScimUser.PhoneNumber("9876543210");
        patch.setPhoneNumbers(Collections.singletonList(newNumber));
        user.patch(patch);
        assertThat(user.getPhoneNumbers()).hasSize(2);
        assertThat(user.getPhoneNumbers().getFirst().getValue()).isEqualTo(newNumber.getValue());
    }

    @Test
    void patchUserDropPhone() {
        patch.getMeta().setAttributes(new String[]{"PhOnEnUmBeRs"});
        user.patch(patch);
        assertThat(patch.getPhoneNumbers()).isNull();

        ScimUser.PhoneNumber newNumber = new ScimUser.PhoneNumber("9876543210");
        patch.setPhoneNumbers(Collections.singletonList(newNumber));
        user.patch(patch);
        assertThat(user.getPhoneNumbers()).hasSize(1);
        assertThat(user.getPhoneNumbers().getFirst().getValue()).isEqualTo(newNumber.getValue());
    }

    @Test
    void patchUserDropAndChangePhone() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        user.addPhoneNumber("0123456789");

        patch.getMeta().setAttributes(new String[]{"PhOnEnUmBeRs"});
        ScimUser.PhoneNumber newNumber = new ScimUser.PhoneNumber("9876543210");
        patch.setPhoneNumbers(Collections.singletonList(newNumber));
        user.patch(patch);

        assertThat(user.getPhoneNumbers().getFirst().getValue()).isEqualTo(newNumber.getValue());
    }

    @Test
    void cannotPatchActiveFalse() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");

        ScimUser patchUser = new ScimUser();
        patchUser.setActive(false);
        patchUser.patch(user);

        assertThat(patchUser.isActive()).isTrue();
    }

    @Test
    void cannotPatchVerifiedFalse() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");

        ScimUser patchUser = new ScimUser();
        patchUser.setVerified(false);
        patchUser.patch(user);

        assertThat(patchUser.isActive()).isTrue();
    }

    @Test
    void patchActive() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        user.setActive(false);

        ScimUser patchUser = new ScimUser();
        patchUser.setActive(true);
        patchUser.patch(user);

        assertThat(patchUser.isActive()).isFalse();

        user.setActive(true);
        patchUser.patch(user);
        assertThat(patchUser.isActive()).isTrue();
    }

    @Test
    void scimUserAliasDeserialization() {
        user.setAliasId("aliasId");
        user.setAliasZid("custom");
        String staticJson = "{\"id\":\"id\",\"externalId\":\"\",\"meta\":{\"version\":0},\"userName\":\"uname\",\"name\":{\"formatted\":\"gname fname\",\"familyName\":\"fname\",\"givenName\":\"gname\"},\"emails\":[{\"value\":\"test@example.org\",\"primary\":false}],\"phoneNumbers\":[{\"value\":\"0123456789\"}],\"displayName\":\"display\",\"title\":\"title\",\"locale\":\"en.UTF-8\",\"active\":true,\"verified\":true,\"origin\":\"\",\"aliasZid\":\"custom\",\"aliasId\":\"aliasId\",\"password\":\"password\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}";
        assertThat(JsonUtils.readValue(staticJson, ScimUser.class)).isEqualTo(user);
    }

    @Test
    void patchVerified() {
        user.setVerified(false);
        patch.setVerified(true);
        user.patch(patch);
        assertThat(user.isVerified()).isTrue();
    }
}
