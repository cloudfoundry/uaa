/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Group;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

/**
 * @author Luke Taylor
 */
public class ScimUserTests {

    private static final String SCHEMAS = "\"schemas\": [\"urn:scim:schemas:core:1.0\"],";

    @Test
    public void minimalJsonMapsToUser() throws Exception {
        String minimal = "{" + SCHEMAS +
                        "  \"userName\": \"bjensen@example.com\"\n" +
                        "}";

        ScimUser user = JsonUtils.readValue(minimal, ScimUser.class);
        assertEquals("bjensen@example.com", user.getUserName());
        assertEquals(null, user.getPassword());
    }

    @Test
    public void passwordJsonMapsToUser() throws Exception {
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
    public void userWithGroupsMapsToJson() throws Exception {
        ScimUser user = new ScimUser();
        user.setId("123");
        user.setUserName("joe");
        user.setGroups(Collections.singleton(new Group(null, "foo")));

        String json = JsonUtils.writeValueAsString(user);
        // System.err.println(json);
        assertTrue(json.contains("\"groups\":"));
    }

    @Test
    public void emailsAreMappedCorrectly() throws Exception {
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
        // System.out.println(mapper.writeValueAsString(user));
    }

    @Test
    public void groupsAreMappedCorrectly() throws Exception {
        String json = "{ \"userName\":\"bjensen\"," +
                        "\"groups\": [\n" +
                        "{\"value\": \"12345\",\"display\": \"uaa.admin\"}," +
                        "{\"value\": \"123456\",\"display\": \"dash.admin\"}" +
                        "],\n" +
                        "\"schemas\":[\"urn:scim:schemas:core:1.0\"]}";
        ScimUser user = JsonUtils.readValue(json, ScimUser.class);
        assertEquals(2, user.getGroups().size());
        // System.out.println(mapper.writeValueAsString(user));
    }

    @Test
    public void datesAreMappedCorrectly() throws Exception {
        String json = "{ \"userName\":\"bjensen\"," +
                        "\"meta\":{\"version\":10,\"created\":\"2011-11-30T10:46:16.475Z\"}}";
        ScimUser user = JsonUtils.readValue(json, ScimUser.class);
        assertEquals(10, user.getVersion());
        assertEquals("2011-11-30", new SimpleDateFormat("yyyy-MM-dd").format(user.getMeta().getCreated()));
        // System.out.println(mapper.writeValueAsString(user));
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

        assertFalse(roz.isVerified());
        roz.setVerified(true);
        assertTrue(roz.isVerified());


    }

    @Test
    public void testSpelFilter() throws Exception {
        ScimUser user = new ScimUser();
        user.setId("123");
        user.setUserName("joe");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("foo@bar.com");
        user.setEmails(Arrays.asList(email));
        StandardEvaluationContext context = new StandardEvaluationContext(user);
        assertTrue(new SpelExpressionParser().parseExpression(
                        "userName == 'joe' and !(emails.?[value=='foo@bar.com']).empty").getValue(context,
                        Boolean.class));
    }

    @Test
    public void testSetPrimaryEmail() throws Exception {
        ScimUser user = new ScimUser();


        assertNull(user.getPrimaryEmail());
        user.setPrimaryEmail("email0@bar.com");
        assertEquals("email0@bar.com", user.getPrimaryEmail());

        ScimUser.Email email1 = new ScimUser.Email();
        email1.setValue("email1@bar.com");
        user.setEmails(new LinkedList<>(Arrays.asList(email1)));
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
    public void testGroupSettersGetters() throws Exception {
        Group group = new Group("id", "display", Group.Type.DIRECT);
        group.setType(Group.Type.DIRECT);
        assertEquals(Group.Type.DIRECT, group.getType());
        group.setType(Group.Type.INDIRECT);
        assertEquals(Group.Type.INDIRECT, group.getType());
        group.setType(null);
        assertNull(group.getType());

        Group group1 = new Group("id", "display", Group.Type.DIRECT);
        Group group2 = new Group("id", "display", Group.Type.DIRECT);
        assertTrue(group1.equals(group2));
        assertTrue(group2.equals(group1));
        assertTrue(group1.equals(group1));
        assertTrue(group2.equals(group2));
        assertFalse(group1.equals(null));
        assertFalse(group1.equals(new Object()));
        group1.setValue(null);
        assertFalse(group1.equals(group2));
        assertFalse(group2.equals(group1));
        group2.setValue(null);
        assertTrue(group1.equals(group2));
        group1.setDisplay(null);
        assertFalse(group1.equals(group2));
        assertFalse(group2.equals(group1));
        group2.setDisplay(null);
        assertTrue(group1.equals(group2));
        assertNotNull(group2.toString());
    }

    @Test
    public void testName() throws Exception {
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
    public void testEmail() throws Exception {
        ScimUser.Email email1 = new ScimUser.Email();
        ScimUser.Email email2 = new ScimUser.Email();
        assertTrue(email1.equals(email2));
        assertTrue(email2.equals(email1));
        assertEquals(email1.hashCode(), email2.hashCode());
        email1.setPrimary(true);
        assertFalse(email1.equals(email2));
        assertFalse(email2.equals(email1));
        email2.setPrimary(true);
        assertTrue(email1.equals(email2));
        assertTrue(email2.equals(email1));
        assertEquals(email1.hashCode(), email2.hashCode());
        email1.setType("work");
        assertFalse(email1.equals(email2));
        assertFalse(email2.equals(email1));
        email2.setType("home");
        assertFalse(email1.equals(email2));
        assertFalse(email2.equals(email1));
        email2.setType("work");
        assertTrue(email1.equals(email2));
        assertTrue(email2.equals(email1));
        assertEquals(email1.hashCode(), email2.hashCode());
        email1.setValue("value@value.org");
        assertFalse(email1.equals(email2));
        assertFalse(email2.equals(email1));
        email2.setValue("value@value.org");
        assertTrue(email1.equals(email2));
        assertTrue(email2.equals(email1));
        assertEquals(email1.hashCode(), email2.hashCode());
    }

    @Test
    public void testPhoneNumber() throws Exception {
        ScimUser.PhoneNumber p1 = new ScimUser.PhoneNumber();
        assertNull(p1.getType());
        assertNull(p1.getValue());
        p1.setValue("value");
        p1.setType("type");
        assertEquals("value",p1.getValue());
        assertEquals("type", p1.getType());
        ScimUser user = new ScimUser();
        user.setPhoneNumbers(Arrays.asList(p1));
        try {
            p1.setType(null);
            user.addPhoneNumber(p1.getValue());
            fail();
        }catch (IllegalArgumentException x) {

        }

    }
}
