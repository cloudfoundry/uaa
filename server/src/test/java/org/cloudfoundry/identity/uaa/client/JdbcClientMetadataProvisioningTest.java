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
package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class JdbcClientMetadataProvisioningTest extends JdbcTestBase {

    public static final String CLIENT_NAME = "Test name";
    JdbcClientMetadataProvisioning db;

    private String randomGUID = "4097895b-ebc1-4732-b6e5-2c33dd2c7cd1";
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(8);

    @Before
    public void createDatasource() throws Exception {
        MultitenantJdbcClientDetailsService clientService = new MultitenantJdbcClientDetailsService(jdbcTemplate);
        db = new JdbcClientMetadataProvisioning(clientService, clientService, jdbcTemplate);
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void constraintViolation_WhenNoMatchingClientFound() throws Exception {
        ClientMetadata clientMetadata = createTestClientMetadata(generator.generate(), true, new URL("http://app.launch/url"), base64EncodedImg);
        db.update(clientMetadata);
    }

    @Test
    public void retrieveClientMetadata() throws Exception {
        String clientId = generator.generate();
        jdbcTemplate.execute(
            String.format("insert into oauth_client_details(client_id, identity_zone_id, created_by) values ('%s', '%s', '%s')",
                clientId, IdentityZone.getUaa().getId(), randomGUID)
            );
        ClientMetadata clientMetadata = createTestClientMetadata(clientId, true, new URL("http://app.launch/url"), base64EncodedImg);
        ClientMetadata createdClientMetadata = db.update(clientMetadata);

        ClientMetadata retrievedClientMetadata = db.retrieve(createdClientMetadata.getClientId());

        assertThat(retrievedClientMetadata.getClientId(), is(clientMetadata.getClientId()));
        assertThat(retrievedClientMetadata.getIdentityZoneId(), is(IdentityZone.getUaa().getId()));
        assertThat(retrievedClientMetadata.isShowOnHomePage(), is(clientMetadata.isShowOnHomePage()));
        assertThat(retrievedClientMetadata.getAppLaunchUrl(), is(clientMetadata.getAppLaunchUrl()));
        assertThat(retrievedClientMetadata.getAppIcon(), is(clientMetadata.getAppIcon()));
        assertThat(retrievedClientMetadata.getCreatedBy(), is(clientMetadata.getCreatedBy()));
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void retrieveClientMetadata_ThatDoesNotExist() throws Exception {
        String clientId = generator.generate();
        db.retrieve(clientId);
    }

    @Test
    public void retrieveAllClientMetadata() throws Exception {
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZone.getUaa().getId() + "')");
        ClientMetadata clientMetadata1 = createTestClientMetadata(clientId, true, new URL("http://app.launch/url"), base64EncodedImg);
        db.update(clientMetadata1);
        String clientId2 = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId2 + "', '" + IdentityZone.getUaa().getId() + "')");
        ClientMetadata clientMetadata2 = createTestClientMetadata(clientId2, true, new URL("http://app.launch/url"), base64EncodedImg);
        db.update(clientMetadata2);

        List<ClientMetadata> clientMetadatas = db.retrieveAll();


        assertThat(clientMetadatas, PredicateMatcher.<ClientMetadata>has(m -> m.getClientId().equals(clientId)));
        assertThat(clientMetadatas, PredicateMatcher.<ClientMetadata>has(m -> m.getClientId().equals(clientId2)));
    }

    @Test
    public void updateClientMetadata() throws Exception {
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZone.getUaa().getId() + "')");
        ClientMetadata newClientMetadata = createTestClientMetadata(clientId, false, new URL("http://updated.app/launch/url"), base64EncodedImg);

        ClientMetadata updatedClientMetadata = db.update(newClientMetadata);

        assertThat(updatedClientMetadata.getClientId(), is(clientId));
        assertThat(updatedClientMetadata.getIdentityZoneId(), is(IdentityZone.getUaa().getId()));
        assertThat(updatedClientMetadata.isShowOnHomePage(), is(newClientMetadata.isShowOnHomePage()));
        assertThat(updatedClientMetadata.getAppLaunchUrl(), is(newClientMetadata.getAppLaunchUrl()));
        assertThat(updatedClientMetadata.getAppIcon(), is(newClientMetadata.getAppIcon()));
    }

    @Test
    public void test_set_and_get_ClientName() throws Exception {
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZoneHolder.get().getId() + "')");
        ClientMetadata data = createTestClientMetadata(clientId,
                                                       false,
                                                       null,
                                                       null);
        data.setClientName(CLIENT_NAME);
        db.update(data);
        data = db.retrieve(clientId);
        assertEquals(CLIENT_NAME, data.getClientName());
    }

    private ClientMetadata createTestClientMetadata(String clientId, boolean showOnHomePage, URL appLaunchUrl, String appIcon) throws MalformedURLException {
        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setClientId(clientId);
        clientMetadata.setShowOnHomePage(showOnHomePage);
        clientMetadata.setAppLaunchUrl(appLaunchUrl);
        clientMetadata.setAppIcon(appIcon);
        clientMetadata.setCreatedBy(randomGUID);
        return clientMetadata;
    }

    private static final String base64EncodedImg = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAXRQTFRFAAAAOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ozk4Ojo6Ojk5NkZMFp/PFqDPNkVKOjo6Ojk5MFhnEq3nEqvjEqzjEbDpMFdlOjo5Ojo6Ojo6Ozg2GZ3TFqXeFKfgF6DVOjo6Ozg2G5jPGZ7ZGKHbGZvROjo6Ojo5M1FfG5vYGp3aM1BdOjo6Ojo6Ojk4KHWeH5PSHpTSKHSbOjk4Ojo6Ojs8IY/QIY/QOjs7Ojo6Ojo6Ozc0JYfJJYjKOzYyOjo5Ozc0KX7AKH/AOzUxOjo5Ojo6Ojo6Ojo6Ojs8LHi6LHi6Ojs7Ojo6Ojo6Ojo6Ojo6Ojo6L3K5L3S7LnW8LnS7Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6NlFvMmWeMmaeNVJwOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojk5Ojk4Ojk4Ojk5Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6FaXeFabfGZ/aGKDaHJnVG5rW////xZzURgAAAHV0Uk5TAAACPaXbAVzltTa4MykoM5HlPY/k5Iw85QnBs2D7+lzAtWD7+lyO6EKem0Ey47Mx2dYvtVZVop5Q2i4qlZAnBiGemh0EDXuddqypcHkShPJwYufmX2rvihSJ+qxlg4JiqP2HPtnW1NjZ2svRVAglGTi91RAXr3/WIQAAAAFiS0dEe0/StfwAAAAJcEhZcwAAAEgAAABIAEbJaz4AAADVSURBVBjTY2BgYGBkYmZhZWVhZmJkAANGNnYODk5ODg52NrAIIyMXBzcPLx8/NwcXIyNYQEBQSFhEVExcQgAiICklLSNbWiYnLy0lCRFQUFRSLq9QUVVUgAgwqqlraFZWaWmrqzFCTNXR1dM3MDQy1tWB2MvIaMJqamZuYWnCCHeIlbWNrZ0VG5QPFLF3cHRydoErcHVz9/D08nb3kYSY6evnHxAYFBwSGhYeAbbWNzIqOiY2Lj4hMckVoiQ5JTUtPSMzKzsH6pfcvPyCwqKc4pJcoAAA2pghnaBVZ0kAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTUtMTAtMDhUMTI6NDg6MDkrMDA6MDDsQS6eAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE1LTEwLTA4VDEyOjQ4OjA5KzAwOjAwnRyWIgAAAEZ0RVh0c29mdHdhcmUASW1hZ2VNYWdpY2sgNi43LjgtOSAyMDE0LTA1LTEyIFExNiBodHRwOi8vd3d3LmltYWdlbWFnaWNrLm9yZ9yG7QAAAAAYdEVYdFRodW1iOjpEb2N1bWVudDo6UGFnZXMAMaf/uy8AAAAYdEVYdFRodW1iOjpJbWFnZTo6aGVpZ2h0ADE5Mg8AcoUAAAAXdEVYdFRodW1iOjpJbWFnZTo6V2lkdGgAMTky06whCAAAABl0RVh0VGh1bWI6Ok1pbWV0eXBlAGltYWdlL3BuZz+yVk4AAAAXdEVYdFRodW1iOjpNVGltZQAxNDQ0MzA4NDg5qdC9PQAAAA90RVh0VGh1bWI6OlNpemUAMEJClKI+7AAAAFZ0RVh0VGh1bWI6OlVSSQBmaWxlOi8vL21udGxvZy9mYXZpY29ucy8yMDE1LTEwLTA4LzJiMjljNmYwZWRhZWUzM2ViNmM1Mzg4ODMxMjg3OTg1Lmljby5wbmdoJKG+AAAAAElFTkSuQmCC";

}
