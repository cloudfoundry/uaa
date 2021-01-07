/*******************************************************************************
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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.text.SimpleDateFormat;
import java.util.*;

import static org.junit.Assert.*;

/**
 * @author Luke Taylor
 */
public class ScimUserTests {

    private static final String SCHEMAS = "\"schemas\": [\"urn:scim:schemas:core:1.0\"],";
    private ScimUser user;
    private ScimUser patch;

    @Before
    public void createUserToBePatched() {
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
    public void testSerializeNullPhoneNumber() {
        ScimUser user = new ScimUser("id","username","giveName","familyName");
        String json = JsonUtils.writeValueAsString(user);
        ScimUser user1 = JsonUtils.readValue(json, ScimUser.class);

        user.setPhoneNumbers(null);
        json = JsonUtils.writeValueAsString(user);
        user1 = JsonUtils.readValue(json, ScimUser.class);

        json = json.replace("\"id\":\"id\"", "\"id\":\"id\", \"phoneNumbers\":[]");
        user1 = JsonUtils.readValue(json, ScimUser.class);
        assertNotNull(user1.getPhoneNumbers());

        json = json.replace("\"phoneNumbers\":[]", "\"phoneNumbers\":null");
        user1 = JsonUtils.readValue(json, ScimUser.class);
        assertNotNull(user1.getPhoneNumbers());


    }

    @Test
    public void test_logon_timestamps_are_null() {
        String oldJson = "{\"id\":\"78df8903-58e9-4a1e-8e22-b0421f7d6d70\",\"meta\":{\"version\":0,\"created\":\"2015-08-21T15:09:26.830Z\",\"lastModified\":\"2015-08-21T15:09:26.830Z\"},\"userName\":\"jo!!!@foo.com\",\"name\":{\"familyName\":\"User\",\"givenName\":\"Jo\"},\"emails\":[{\"value\":\"jo!!!@foo.com\",\"primary\":false}],\"active\":true,\"verified\":false,\"origin\":\"uaa\",\"zoneId\":\"uaa\",\"passwordLastModified\":null,\"schemas\":[\"urn:scim:schemas:core:1.0\"]}";
        for (String json : Arrays.asList(oldJson, JsonUtils.writeValueAsString(new ScimUser()))) {
            ScimUser user = JsonUtils.readValue(json, ScimUser.class);
            assertNull(json, user.getPreviousLogonTime());
            assertNull(json, user.getLastLogonTime());
        }
    }

    @Test
    public void testDeserializeNullPasswordLastModified() {
        String json = "{\"id\":\"78df8903-58e9-4a1e-8e22-b0421f7d6d70\",\"meta\":{\"version\":0,\"created\":\"2015-08-21T15:09:26.830Z\",\"lastModified\":\"2015-08-21T15:09:26.830Z\"},\"userName\":\"jo!!!@foo.com\",\"name\":{\"familyName\":\"User\",\"givenName\":\"Jo\"},\"emails\":[{\"value\":\"jo!!!@foo.com\",\"primary\":false}],\"active\":true,\"verified\":false,\"origin\":\"uaa\",\"zoneId\":\"uaa\",\"passwordLastModified\":null,\"schemas\":[\"urn:scim:schemas:core:1.0\"]}";
        JsonUtils.readValue(json, ScimUser.class);
    }

    @Test
    public void minimalJsonMapsToUser() {
        String minimal = "{" + SCHEMAS +
                        "  \"userName\": \"bjensen@example.com\"\n" +
                        "}";

        ScimUser user = JsonUtils.readValue(minimal, ScimUser.class);
        assertEquals("bjensen@example.com", user.getUserName());
        assertNull(user.getPassword());
    }

    @Test
    public void passwordJsonMapsToUser() {
        String minimal = "{" + SCHEMAS +
                        "  \"userName\": \"bjensen@example.com\",\n" +
                        "  \"password\": \"foo\"\n" +
                        "}";

        ScimUser user = JsonUtils.readValue(minimal, ScimUser.class);
        assertEquals("foo", user.getPassword());
    }

    @Test
    public void minimalUserMapsToJson() throws Exception {
        ScimUser user = new ScimUser();
        user.setId("123");
        user.setUserName("joe");
        user.getMeta().setCreated(new SimpleDateFormat("yyyy-MM-dd").parse("2011-11-30"));

        String json = JsonUtils.writeValueAsString(user);
        // System.err.println(json);
        assertTrue(json.contains("\"userName\":\"joe\""));
        assertTrue(json.contains("\"id\":\"123\""));
        assertTrue(json.contains("\"meta\":"));
        assertTrue(json.contains("\"created\":\"2011-11-30"));
        assertTrue(json.matches(".*\\\"created\\\":\\\"([0-9-]*-?)T([0-9:.]*)Z\\\".*"));
        assertFalse(json.contains("\"lastModified\":"));

    }

    @Test
    public void anotherUserMapsToJson() throws Exception {
        ScimUser user = new ScimUser();
        user.setId("123");
        user.setUserName("joe");
        user.getMeta().setCreated(new SimpleDateFormat("yyyy-MM-dd").parse("2011-11-30"));
        user.addEmail("joe@test.org");
        user.addPhoneNumber("+1-222-1234567");

        String json = JsonUtils.writeValueAsString(user);
        // System.err.println(json);
        assertTrue(json.contains("\"emails\":"));
        assertTrue(json.contains("\"phoneNumbers\":"));

    }

    @Test
    public void userWithGroupsMapsToJson() {
        ScimUser user = new ScimUser();
        user.setId("123");
        user.setUserName("joe");
        user.setGroups(Collections.singleton(new Group(null, "foo")));

        String json = JsonUtils.writeValueAsString(user);
        // System.err.println(json);
        assertTrue(json.contains("\"groups\":"));
    }

    @Test
    public void emailsAreMappedCorrectly() {
        String json = "{ \"userName\":\"bjensen\"," +
                        "\"emails\": [\n" +
                        "{\"value\": \"bj@jensen.org\",\"type\": \"other\"}," +
                        "{\"value\": \"bjensen@example.com\", \"type\": \"work\",\"primary\": true}," +
                        "{\"value\": \"babs@jensen.org\",\"type\": \"home\"}" +
                        "],\n" +
                        "\"schemas\":[\"urn:scim:schemas:core:1.0\"]}";
        ScimUser user = JsonUtils.readValue(json, ScimUser.class);
        assertEquals(3, user.getEmails().size());
        assertEquals("bjensen@example.com", user.getEmails().get(1).getValue());
        assertEquals("babs@jensen.org", user.getEmails().get(2).getValue());
        assertEquals("bjensen@example.com", user.getPrimaryEmail());
        assertFalse(user.getEmails().get(0).isPrimary());
    }

    @Test
    public void groupsAreMappedCorrectly() {
        String json = "{ \"userName\":\"bjensen\"," +
                        "\"groups\": [\n" +
                        "{\"value\": \"12345\",\"display\": \"uaa.admin\"}," +
                        "{\"value\": \"123456\",\"display\": \"dash.admin\"}" +
                        "],\n" +
                        "\"schemas\":[\"urn:scim:schemas:core:1.0\"]}";
        ScimUser user = JsonUtils.readValue(json, ScimUser.class);
        assertEquals(2, user.getGroups().size());
    }

    @Test
    public void datesAreMappedCorrectly() {
        String json = "{ \"userName\":\"bjensen\"," +
                        "\"meta\":{\"version\":10,\"created\":\"2011-11-30T10:46:16.475Z\"}}";
        ScimUser user = JsonUtils.readValue(json, ScimUser.class);
        assertEquals(10, user.getVersion());
        assertEquals("2011-11-30", new SimpleDateFormat("yyyy-MM-dd").format(user.getMeta().getCreated()));
    }

    @Test
    public void basicNamesAreMappedCorrectly() {
        ScimUser roz = new ScimUser("1234", "roz", "Roslyn", "MacRae");
        assertEquals("1234", roz.getId());
        assertEquals("roz", roz.getUserName());
        assertEquals("Roslyn", roz.getGivenName());
        assertEquals("MacRae", roz.getFamilyName());
        roz.setId("12345");
        assertEquals("12345", roz.getId());
        assertEquals("roz", roz.getUserName());
        assertEquals("Roslyn", roz.getGivenName());
        assertEquals("MacRae", roz.getFamilyName());
        roz.setUserName("roz1");
        assertEquals("12345", roz.getId());
        assertEquals("roz1", roz.getUserName());
        assertEquals("Roslyn", roz.getGivenName());
        assertEquals("MacRae", roz.getFamilyName());
        ScimUser.Name name = new ScimUser.Name("Roslyn","MacRae");
        roz.setName(name);
        assertSame(name, roz.getName());
        assertNull(roz.getApprovals());
        Set<Approval> approvals = new HashSet<>();
        roz.setApprovals(approvals);
        assertSame(approvals, roz.getApprovals());
        List<ScimUser.PhoneNumber> phoneNumbers = new LinkedList<>();
        ScimUser.PhoneNumber p1 = new ScimUser.PhoneNumber();
        phoneNumbers.add(p1);
        roz.setPhoneNumbers(phoneNumbers);
        assertNotNull(roz.getPhoneNumbers());
        assertTrue(roz.getPhoneNumbers().isEmpty());
        p1.setValue("value");
        p1.setType("type");
        roz.setPhoneNumbers(phoneNumbers);
        assertNotNull(roz.getPhoneNumbers());
        assertEquals(1, roz.getPhoneNumbers().size());

        assertNull(roz.getDisplayName());
        roz.setDisplayName("DisplayName");
        assertEquals("DisplayName", roz.getDisplayName());

        assertNull(roz.getProfileUrl());
        roz.setProfileUrl("ProfileUrl");
        assertEquals("ProfileUrl", roz.getProfileUrl());

        assertNull(roz.getTitle());
        roz.setTitle("Title");
        assertEquals("Title", roz.getTitle());

        assertNull(roz.getUserType());
        roz.setUserType("UserType");
        assertEquals("UserType", roz.getUserType());

        assertNull(roz.getPreferredLanguage());
        roz.setPreferredLanguage("PreferredLanguage");
        assertEquals("PreferredLanguage", roz.getPreferredLanguage());

        assertNull(roz.getLocale());
        roz.setLocale("Locale");
        assertEquals("Locale", roz.getLocale());

        assertTrue(roz.isActive());
        roz.setActive(false);
        assertFalse(roz.isActive());

        assertNull(roz.getTimezone());
        roz.setTimezone("Timezone");
        assertEquals("Timezone", roz.getTimezone());

        assertEquals("",roz.getOrigin());
        roz.setOrigin("Origin");
        assertEquals("Origin", roz.getOrigin());

        assertEquals("",roz.getExternalId());
        roz.setExternalId("ExternalId");
        assertEquals("ExternalId", roz.getExternalId());

        assertNull(roz.getNickName());
        roz.setNickName("NickName");
        assertEquals("NickName", roz.getNickName());

        assertTrue(roz.isVerified());
        roz.setVerified(false);
        assertFalse(roz.isVerified());
    }

    @Test
    public void testSpelFilter() {
        ScimUser user = new ScimUser();
        user.setId("123");
        user.setUserName("joe");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("foo@bar.com");
        user.setEmails(Collections.singletonList(email));
        StandardEvaluationContext context = new StandardEvaluationContext(user);
        assertTrue(new SpelExpressionParser().parseExpression(
                        "userName == 'joe' and !(emails.?[value=='foo@bar.com']).empty").getValue(context,
                        Boolean.class));
    }

    @Test
    public void testSetPrimaryEmail() {
        ScimUser user = new ScimUser();


        assertNull(user.getPrimaryEmail());
        user.setPrimaryEmail("email0@bar.com");
        assertEquals("email0@bar.com", user.getPrimaryEmail());

        ScimUser.Email email1 = new ScimUser.Email();
        email1.setValue("email1@bar.com");
        user.setEmails(new LinkedList<>(Collections.singletonList(email1)));
        assertEquals("email1@bar.com", user.getPrimaryEmail());

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

        Assert.assertEquals("new@example.com", user.getPrimaryEmail());

        Assert.assertEquals(Arrays.asList(newEmail, email2, email3), user.getEmails());

        try {
            user.addEmail("email3@bar.com");
            fail();
        } catch (IllegalArgumentException x) {
            assertEquals("Already contains email email3@bar.com", x.getMessage());
        }
        user.setUserName("userName");
        user.setNickName("nickName");
        user.setName(new ScimUser.Name("givenName", "familyName"));
        assertNotNull(user.wordList());
        assertFalse(user.wordList().isEmpty());
        assertEquals(7, user.wordList().size());
    }

    @Test
    public void testGroupSettersGetters() {
        Group group = new Group("id", "display", Group.Type.DIRECT);
        group.setType(Group.Type.DIRECT);
        assertEquals(Group.Type.DIRECT, group.getType());
        group.setType(Group.Type.INDIRECT);
        assertEquals(Group.Type.INDIRECT, group.getType());
        group.setType(null);
        assertNull(group.getType());

        Group group1 = new Group("id", "display", Group.Type.DIRECT);
        Group group2 = new Group("id", "display", Group.Type.DIRECT);
        assertEquals(group1, group2);
        assertEquals(group2, group1);
        assertEquals(group1, group1);
        assertEquals(group2, group2);
        assertNotEquals(null, group1);
        assertNotEquals(group1, new Object());
        group1.setValue(null);
        assertNotEquals(group1, group2);
        assertNotEquals(group2, group1);
        group2.setValue(null);
        assertEquals(group1, group2);
        group1.setDisplay(null);
        assertNotEquals(group1, group2);
        assertNotEquals(group2, group1);
        group2.setDisplay(null);
        assertEquals(group1, group2);
        assertNotNull(group2.toString());
    }

    @Test
    public void testName() {
        ScimUser.Name name1 = new ScimUser.Name();
        assertNull(name1.getFamilyName());
        assertNull(name1.getFormatted());
        assertNull(name1.getGivenName());
        assertNull(name1.getHonorificPrefix());
        assertNull(name1.getHonorificSuffix());
        assertNull(name1.getMiddleName());

        name1.setFamilyName("familyName");
        assertEquals("familyName", name1.getFamilyName());
        name1.setGivenName("givenName");
        assertEquals("givenName", name1.getGivenName());
        assertNull(name1.getFormatted());
        name1.setHonorificPrefix("honorificPrefix");
        assertEquals("honorificPrefix", name1.getHonorificPrefix());
        name1.setHonorificSuffix("honorificSuffix");
        assertEquals("honorificSuffix", name1.getHonorificSuffix());
        name1.setFormatted("formatted");
        assertEquals("formatted", name1.getFormatted());
        name1.setMiddleName("middle");
        assertEquals("middle", name1.getMiddleName());
        ScimUser.Name name2 = new ScimUser.Name("givenName", "familyName");
        assertEquals("givenName familyName", name2.getFormatted());
    }

    @Test
    public void testEmail() {
        ScimUser.Email email1 = new ScimUser.Email();
        ScimUser.Email email2 = new ScimUser.Email();
        assertEquals(email1, email2);
        assertEquals(email2, email1);
        assertEquals(email1.hashCode(), email2.hashCode());
        email1.setPrimary(true);
        assertNotEquals(email1, email2);
        assertNotEquals(email2, email1);
        email2.setPrimary(true);
        assertEquals(email1, email2);
        assertEquals(email2, email1);
        assertEquals(email1.hashCode(), email2.hashCode());
        email1.setType("work");
        assertNotEquals(email1, email2);
        assertNotEquals(email2, email1);
        email2.setType("home");
        assertNotEquals(email1, email2);
        assertNotEquals(email2, email1);
        email2.setType("work");
        assertEquals(email1, email2);
        assertEquals(email2, email1);
        assertEquals(email1.hashCode(), email2.hashCode());
        email1.setValue("value@value.org");
        assertNotEquals(email1, email2);
        assertNotEquals(email2, email1);
        email2.setValue("value@value.org");
        assertEquals(email1, email2);
        assertEquals(email2, email1);
        assertEquals(email1.hashCode(), email2.hashCode());
    }

    @Test
    public void testPhoneNumber() {
        ScimUser.PhoneNumber p1 = new ScimUser.PhoneNumber();
        assertNull(p1.getType());
        assertNull(p1.getValue());
        p1.setValue("value");
        p1.setType("type");
        assertEquals("value",p1.getValue());
        assertEquals("type", p1.getType());
        ScimUser user = new ScimUser();
        user.setPhoneNumbers(Collections.singletonList(p1));
        try {
            p1.setType(null);
            user.addPhoneNumber(p1.getValue());
            fail();
        }catch (IllegalArgumentException ignored) {

        }

    }

    @Test
    public void testPasswordLastModified() {
        ScimUser user = new ScimUser();
        assertNull(user.getPasswordLastModified());
        user.setId("someid");
        assertSame(user.getMeta().getCreated(), user.getPasswordLastModified());

        Date d = new Date(System.currentTimeMillis());
        user.setPasswordLastModified(d);
        assertNotNull(user.getPasswordLastModified());
        assertSame(d, user.getPasswordLastModified());

    }

    @Test
    public void user_verified_byDefault() {
        ScimUser user = new ScimUser();
        assertTrue(user.isVerified());
    }

    @Test
    public void test_patch_last_logon() {
        patch.setLastLogonTime(System.currentTimeMillis());
        user.patch(patch);
        assertNull(user.getLastLogonTime());
    }

    @Test
    public void test_patch_previous_logon() {
        patch.setPreviousLogonTime(System.currentTimeMillis());
        user.patch(patch);
        assertNull(user.getPreviousLogonTime());
    }


    @Test
    public void testPatchUserSetPrimaryEmail() {
        ScimUser.Email newMail = new ScimUser.Email();
        newMail.setPrimary(true);
        newMail.setValue("newTest@example.org");
        patch.setEmails(Collections.singletonList(newMail));
        user.patch(patch);
        assertEquals("newTest@example.org", user.getPrimaryEmail());
    }

    @Test
    public void testPatchUserSelectPrimaryEmailFromList() {
        ScimUser.Email newMail = new ScimUser.Email();
        newMail.setPrimary(false);
        newMail.setValue("newTest@example.org");
        ScimUser.Email secondMail = new ScimUser.Email();
        newMail.setPrimary(true);
        newMail.setValue("secondTest@example.org");
        patch.setEmails(Arrays.asList(newMail, secondMail));
        user.patch(patch);
        assertEquals("secondTest@example.org", user.getPrimaryEmail());
        //complex property is merged. not replaced.
        assertEquals(3, user.getEmails().size());

        //drop the email first
        patch.getMeta().setAttributes(new String[] {"emails"});
        user.patch(patch);
        assertEquals("secondTest@example.org", user.getPrimaryEmail());
        assertEquals(2, user.getEmails().size());
    }

    @Test
    public void testPatchUserChangeUserName() {
        patch.setUserName("newUsername");
        user.patch(patch);
        assertEquals("newUsername", user.getUserName());

        //username is a required field
        patch.getMeta().setAttributes(new String[] {"username"});
        patch.setUserName(null);
        try {
            user.patch(patch);
            fail("username is a required field, can't nullify it.");
        } catch (IllegalArgumentException ignored) {
        }
        assertNotNull(user.getUserName());

        //we can drop and set the username again
        patch.setUserName("newUsername2");
        user.patch(patch);
        assertEquals("newUsername2", user.getUserName());
    }

    @Test
    public void testPatchUserChangeName() {
        patch.setName(new ScimUser.Name("Test", "Name"));
        user.patch(patch);
        assertEquals("Test", user.getName().getGivenName());
        assertEquals("Name", user.getName().getFamilyName());
    }

    @Test
    public void testPatchUserDropName() {
        patch.setName(new ScimUser.Name("given-only",null));
        user.patch(patch);
        assertEquals("given-only", user.getName().getGivenName());
        assertNotNull(user.getName().getFamilyName());

        patch.getMeta().setAttributes(new String[]{"NAME"});
        user.patch(patch);
        assertEquals("given-only", user.getName().getGivenName());
        assertNull(user.getName().getFamilyName());
    }

    @Test
    public void testPatchUserDropNameSubAttributes() {
        patch.setName(null);
        patch.getMeta().setAttributes(new String[]{"name.givenname"});
        user.patch(patch);
        assertNull(user.getName().getGivenName());
        assertNotNull(user.getName().getFamilyName());

        patch.getMeta().setAttributes(new String[]{"Name.familyname"});
        user.patch(patch);
        assertNull(user.getName().getGivenName());
        assertNull(user.getName().getFamilyName());
    }

    @Test
    public void testPatchUserDropNonUsedAttributes() {
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
        patch.setName(new ScimUser.Name(null,null));
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

        assertEquals(0, pos);














    }

    public void setAndPatchAndValidate(String attribute, int nullable) {
        patch.getMeta().setAttributes(new String[] {attribute});
        user.patch(patch);
        allSet(nullable);
    }

    public void doAssertNull(int skip, int pos, Object value) {
        if (skip<=pos) {
            assertNotNull(value);
        } else {
            assertNull(value);
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
    public void testPatchUserDropAndChangeName() {
        patch.getMeta().setAttributes(new String[]{"NAME"});
        user.patch(patch);
        assertNull(user.getName().getGivenName());
        assertNull(user.getName().getFamilyName());

        patch.setName(new ScimUser.Name("Test", "Name"));
        user.patch(patch);
        assertEquals("Test", user.getName().getGivenName());
        assertEquals("Name", user.getName().getFamilyName());
    }

    @Test
    public void testPatchUserChangePhone() {
        ScimUser.PhoneNumber newNumber = new ScimUser.PhoneNumber("9876543210");
        patch.setPhoneNumbers(Collections.singletonList(newNumber));
        user.patch(patch);
        assertEquals(2, user.getPhoneNumbers().size());
        assertEquals(newNumber.getValue(), user.getPhoneNumbers().get(0).getValue());
    }

    @Test
    public void testPatchUserDropPhone() {
        patch.getMeta().setAttributes(new String[]{"PhOnEnUmBeRs"});
        user.patch(patch);
        assertNull(patch.getPhoneNumbers());

        ScimUser.PhoneNumber newNumber = new ScimUser.PhoneNumber("9876543210");
        patch.setPhoneNumbers(Collections.singletonList(newNumber));
        user.patch(patch);
        assertEquals(1, user.getPhoneNumbers().size());
        assertEquals(newNumber.getValue(), user.getPhoneNumbers().get(0).getValue());
    }

    @Test
    public void testPatch_Drop_Using_Attributes() {
        String[] s = {
                "username",
                "Name",
                "Emails",
                "hOnEnUmBeRs",
                "DisplayName",
                "NickName",
                "ProfileUrl",
                "Title",
                "PreferredLanguage",
                "Locale",
                "Timezone",
                "Name.familyName",
                "Name.givenName",
                "Name.formatted",
                "Name.honorificPreFix",
                "Name.honorificSuffix",
                "Name.middleName"
        };
    }

    @Test
    public void testPatchUserDropAndChangePhone() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        user.addPhoneNumber("0123456789");

        patch.getMeta().setAttributes(new String[]{"PhOnEnUmBeRs"});
        ScimUser.PhoneNumber newNumber = new ScimUser.PhoneNumber("9876543210");
        patch.setPhoneNumbers(Collections.singletonList(newNumber));
        user.patch(patch);

        assertEquals(newNumber.getValue(), user.getPhoneNumbers().get(0).getValue());
    }

    @Test
    public void testCannotPatchActiveFalse() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");

        ScimUser patchUser = new ScimUser();
        patchUser.setActive(false);
        patchUser.patch(user);

        assertTrue(patchUser.isActive());
    }

    @Test
    public void testCannotPatchVerifiedFalse() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");

        ScimUser patchUser = new ScimUser();
        patchUser.setVerified(false);
        patchUser.patch(user);

        assertTrue(patchUser.isActive());
    }

    @Test
    public void testPatchActive() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        user.setActive(false);

        ScimUser patchUser = new ScimUser();
        patchUser.setActive(true);
        patchUser.patch(user);

        assertFalse(patchUser.isActive());

        user.setActive(true);
        patchUser.patch(user);
        assertTrue(patchUser.isActive());
    }

    @Test
    public void testPatchVerified() {
        user.setVerified(false);
        patch.setVerified(true);
        user.patch(patch);
        assertTrue(user.isVerified());
    }

    @Test
    public void testCustomAttributeAccountNumber() {
        String json = "{\"userName\":\"jbourne\",\"customAttributes\":{\"accountNumber\":12345," +
                "\"ccUserName\":\"jbourne@acme.com\"}}";
        ScimUser user = JsonUtils.readValue(json, ScimUser.class);

        assertEquals(12345, user.getCustomAttributes().get("accountNumber"));
        assertEquals("jbourne@acme.com", user.getCustomAttributes().get("ccUserName"));
    }

    @Test
    public void testCustomAttributeSerialization() {
        ScimUser user = new ScimUser();
        user.setUserName("jbourne");
        LinkedHashMap<String, String> map = new LinkedHashMap<>();
        map.put("accountNumber", "12345");
        map.put("ccUserName", "jbourne@acme.com");
        user.setCustomAttributes(map);

        String json = JsonUtils.writeValueAsString(user);
        ScimUser user1 = JsonUtils.readValue(json, ScimUser.class);

        assertTrue(json.contains("\"accountNumber\":\"12345\""));
        assertTrue(json.contains("\"ccUserName\":\"jbourne@acme.com\""));
        assertEquals("12345", user1.getCustomAttributes().get("accountNumber"));
        assertEquals("jbourne@acme.com", user1.getCustomAttributes().get("ccUserName"));
    }
}
