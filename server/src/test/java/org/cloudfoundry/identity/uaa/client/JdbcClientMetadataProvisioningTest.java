package org.cloudfoundry.identity.uaa.client;

import org.apache.xml.security.utils.Base64;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.net.MalformedURLException;
import java.net.URL;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class JdbcClientMetadataProvisioningTest extends JdbcTestBase {

    JdbcClientMetadataProvisioning db;

    private RandomValueStringGenerator generator = new RandomValueStringGenerator(8);

    @Before
    public void create_datasource() throws Exception {
        db = new JdbcClientMetadataProvisioning(jdbcTemplate);

        // When running hsqldb uncomment these lines to invoke the in-built UI client
//        org.hsqldb.util.DatabaseManagerSwing.main(new String[] {
//                "--url",  "jdbc:hsqldb:mem:uaadb", "--noexit"
//        });
    }
//
//    @Override
//    public void setUp() throws Exception {
//        System.setProperty("spring.profiles.active", "postgresql");
//        super.setUp();
//    }

    @Test
    public void create_clientUIDetails() throws Exception {
        //given
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZone.getUaa().getId() + "')");
        ClientMetaDetails clientMetaDetails = createTestClientUIDetails(clientId, true, new URL("http://app.launch/url"), base64EncodedImg);

        //when a client ui details object is saved
        ClientMetaDetails createdClientMetaDetails = db.create(clientMetaDetails);

        //then
        assertThat(createdClientMetaDetails.getClientId(), is(clientMetaDetails.getClientId()));
        assertThat(createdClientMetaDetails.getIdentityZoneId(), is(IdentityZone.getUaa().getId()));
        assertThat(createdClientMetaDetails.isShowOnHomePage(), is(clientMetaDetails.isShowOnHomePage()));
        assertThat(createdClientMetaDetails.getAppLaunchUrl(), is(clientMetaDetails.getAppLaunchUrl()));
        assertThat(createdClientMetaDetails.getAppIcon(), is(clientMetaDetails.getAppIcon()));
        assertThat(createdClientMetaDetails.getVersion(), is(1));

        //and then app icon that is saved is really the base64 decoded bytes
        byte[] blobbyblob = jdbcTemplate.queryForObject("select app_icon from oauth_client_ui_details where client_id='" + clientId + "'", byte[].class);
        assertThat(blobbyblob, is(Base64.decode(base64EncodedImg)));
    }

    @Test
    public void when_multipleClients_with_theSameNameButDifferentZone_clientUIDetails_correctlyAssociated() throws Exception {
        try {
            //given
            String clientId = generator.generate();
            String otherZoneId = generator.generate();
            IdentityZone otherZone = new IdentityZone();
            otherZone.setId(otherZoneId);
            jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZone.getUaa().getId() + "')");
            jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + otherZoneId + "')");
            ClientMetaDetails clientMetaDetails = createTestClientUIDetails(clientId, true, new URL("http://app.launch/url"), base64EncodedImg);
            IdentityZoneHolder.set(otherZone);

            //when a client is created in another zone
            ClientMetaDetails createdClientMetaDetails = db.create(clientMetaDetails);

            //then expect as such
            assertThat(createdClientMetaDetails.getIdentityZoneId(), is(otherZoneId));
        } finally {
            IdentityZoneHolder.set(IdentityZone.getUaa());
        }
    }

    @Test(expected = DataIntegrityViolationException.class)
    public void constraintViolation_when_noMatchingClientFound() throws Exception {
        //given there is no oauth_client_details record

        //when we attempt to create an client ui details record
        ClientMetaDetails clientMetaDetails = createTestClientUIDetails(generator.generate(), true, new URL("http://app.launch/url"), base64EncodedImg);
        db.create(clientMetaDetails);

        //then we expect a constraint violation
    }

    @Test
    public void retrieve_ClientUIDetails() throws Exception {
        //given
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZone.getUaa().getId() + "')");
        ClientMetaDetails clientMetaDetails = createTestClientUIDetails(clientId, true, new URL("http://app.launch/url"), base64EncodedImg);
        ClientMetaDetails createdClientMetaDetails = db.create(clientMetaDetails);

        //when retrieving the client UI details
        ClientMetaDetails retrievedClientMetaDetails = db.retrieve(createdClientMetaDetails.getClientId());

        //then
        assertThat(retrievedClientMetaDetails.getClientId(), is(clientMetaDetails.getClientId()));
        assertThat(retrievedClientMetaDetails.getIdentityZoneId(), is(IdentityZone.getUaa().getId()));
        assertThat(retrievedClientMetaDetails.isShowOnHomePage(), is(clientMetaDetails.isShowOnHomePage()));
        assertThat(retrievedClientMetaDetails.getAppLaunchUrl(), is(clientMetaDetails.getAppLaunchUrl()));
        assertThat(retrievedClientMetaDetails.getAppIcon(), is(clientMetaDetails.getAppIcon()));
    }

    @Test
    public void update_ClientUIDetails() throws Exception {
        //given
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZone.getUaa().getId() + "')");
        ClientMetaDetails clientMetaDetails = createTestClientUIDetails(clientId, true, new URL("http://app.launch/url"), base64EncodedImg);
        ClientMetaDetails createdClientMetaDetails = db.create(clientMetaDetails);
        ClientMetaDetails newClientMetaDetails = createTestClientUIDetails(clientMetaDetails.getClientId(), false, new URL("http://updated.app/launch/url"), base64EncodedImg);

        //when
        ClientMetaDetails updatedClientMetaDetails = db.update(createdClientMetaDetails.getClientId(), newClientMetaDetails);
        try {
            db.update(createdClientMetaDetails.getClientId(), newClientMetaDetails);
            fail("another update should fail due to incorrect version");
        } catch (OptimisticLockingFailureException olfe) {}

        //then
        assertThat(updatedClientMetaDetails.getClientId(), is(clientMetaDetails.getClientId()));
        assertThat(updatedClientMetaDetails.getIdentityZoneId(), is(IdentityZone.getUaa().getId()));
        assertThat(updatedClientMetaDetails.isShowOnHomePage(), is(newClientMetaDetails.isShowOnHomePage()));
        assertThat(updatedClientMetaDetails.getAppLaunchUrl(), is(newClientMetaDetails.getAppLaunchUrl()));
        assertThat(updatedClientMetaDetails.getAppIcon(), is(newClientMetaDetails.getAppIcon()));
        assertThat(updatedClientMetaDetails.getVersion(), is(clientMetaDetails.getVersion() + 1));
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void delete_ClientUIDetails() throws Exception {
        //given
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZone.getUaa().getId() + "')");
        ClientMetaDetails clientMetaDetails = createTestClientUIDetails(clientId, true, new URL("http://app.launch/url"), base64EncodedImg);
        db.create(clientMetaDetails);

        //when you delete the client ui details
        db.delete(clientMetaDetails.getClientId(), -1);

        //then subsequent retrieval should fail
        db.retrieve(clientMetaDetails.getClientId());
    }

    @Test
    public void deletion_after_version_update() throws Exception {
        //given
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZone.getUaa().getId() + "')");
        ClientMetaDetails clientMetaDetails = createTestClientUIDetails(clientId, true, new URL("http://app.launch/url"), base64EncodedImg);
        ClientMetaDetails createdClientMetaDetails = db.create(clientMetaDetails);
        ClientMetaDetails newClientMetaDetails = createTestClientUIDetails(clientMetaDetails.getClientId(), false, new URL("http://updated.app/launch/url"), base64EncodedImg);
        db.update(createdClientMetaDetails.getClientId(), newClientMetaDetails);

        //when you delete
        try {
            db.delete(clientId, clientMetaDetails.getVersion());
            fail("should fail because wrong version");
        } catch (OptimisticLockingFailureException olfe) {}

        //then succeed with right version
        db.delete(clientId, clientMetaDetails.getVersion() + 1);
    }

    private ClientMetaDetails createTestClientUIDetails(String clientId, boolean showOnHomePage, URL appLaunchUrl, String appIcon) throws MalformedURLException {
        ClientMetaDetails clientMetaDetails = new ClientMetaDetails();
        clientMetaDetails.setClientId(clientId);
        clientMetaDetails.setShowOnHomePage(showOnHomePage);
        clientMetaDetails.setAppLaunchUrl(appLaunchUrl);
        clientMetaDetails.setAppIcon(appIcon);
        clientMetaDetails.setVersion(1);
        return clientMetaDetails;
    }

    private static final String base64EncodedImg = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAXRQTFRFAAAAOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ozk4Ojo6Ojk5NkZMFp/PFqDPNkVKOjo6Ojk5MFhnEq3nEqvjEqzjEbDpMFdlOjo5Ojo6Ojo6Ozg2GZ3TFqXeFKfgF6DVOjo6Ozg2G5jPGZ7ZGKHbGZvROjo6Ojo5M1FfG5vYGp3aM1BdOjo6Ojo6Ojk4KHWeH5PSHpTSKHSbOjk4Ojo6Ojs8IY/QIY/QOjs7Ojo6Ojo6Ozc0JYfJJYjKOzYyOjo5Ozc0KX7AKH/AOzUxOjo5Ojo6Ojo6Ojo6Ojs8LHi6LHi6Ojs7Ojo6Ojo6Ojo6Ojo6Ojo6L3K5L3S7LnW8LnS7Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6NlFvMmWeMmaeNVJwOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojk5Ojk4Ojk4Ojk5Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6FaXeFabfGZ/aGKDaHJnVG5rW////xZzURgAAAHV0Uk5TAAACPaXbAVzltTa4MykoM5HlPY/k5Iw85QnBs2D7+lzAtWD7+lyO6EKem0Ey47Mx2dYvtVZVop5Q2i4qlZAnBiGemh0EDXuddqypcHkShPJwYufmX2rvihSJ+qxlg4JiqP2HPtnW1NjZ2svRVAglGTi91RAXr3/WIQAAAAFiS0dEe0/StfwAAAAJcEhZcwAAAEgAAABIAEbJaz4AAADVSURBVBjTY2BgYGBkYmZhZWVhZmJkAANGNnYODk5ODg52NrAIIyMXBzcPLx8/NwcXIyNYQEBQSFhEVExcQgAiICklLSNbWiYnLy0lCRFQUFRSLq9QUVVUgAgwqqlraFZWaWmrqzFCTNXR1dM3MDQy1tWB2MvIaMJqamZuYWnCCHeIlbWNrZ0VG5QPFLF3cHRydoErcHVz9/D08nb3kYSY6evnHxAYFBwSGhYeAbbWNzIqOiY2Lj4hMckVoiQ5JTUtPSMzKzsH6pfcvPyCwqKc4pJcoAAA2pghnaBVZ0kAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTUtMTAtMDhUMTI6NDg6MDkrMDA6MDDsQS6eAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE1LTEwLTA4VDEyOjQ4OjA5KzAwOjAwnRyWIgAAAEZ0RVh0c29mdHdhcmUASW1hZ2VNYWdpY2sgNi43LjgtOSAyMDE0LTA1LTEyIFExNiBodHRwOi8vd3d3LmltYWdlbWFnaWNrLm9yZ9yG7QAAAAAYdEVYdFRodW1iOjpEb2N1bWVudDo6UGFnZXMAMaf/uy8AAAAYdEVYdFRodW1iOjpJbWFnZTo6aGVpZ2h0ADE5Mg8AcoUAAAAXdEVYdFRodW1iOjpJbWFnZTo6V2lkdGgAMTky06whCAAAABl0RVh0VGh1bWI6Ok1pbWV0eXBlAGltYWdlL3BuZz+yVk4AAAAXdEVYdFRodW1iOjpNVGltZQAxNDQ0MzA4NDg5qdC9PQAAAA90RVh0VGh1bWI6OlNpemUAMEJClKI+7AAAAFZ0RVh0VGh1bWI6OlVSSQBmaWxlOi8vL21udGxvZy9mYXZpY29ucy8yMDE1LTEwLTA4LzJiMjljNmYwZWRhZWUzM2ViNmM1Mzg4ODMxMjg3OTg1Lmljby5wbmdoJKG+AAAAAElFTkSuQmCC";

}