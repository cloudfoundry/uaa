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

package org.cloudfoundry.identity.uaa.scim.remote;

import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Date;
import java.util.List;

/**
 * Remote implementation of
 * {@link org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning} using the
 * Scim endpoints on a remote server.
 * 
 * @author Dave Syer
 * 
 */
@Deprecated
public class RemoteScimUserProvisioning implements ScimUserProvisioning {

    private RestOperations restTemplate = new RestTemplate();

    private String baseUrl = "https://uaa.cloudfoundry.com";

    /**
     * @param restTemplate the rest template to set
     */
    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * @param baseUrl the base url to set to the SCIM server
     */
    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    @Override
    public ScimUser retrieve(String id) throws ScimResourceNotFoundException {
        return restTemplate.getForObject(baseUrl + "/User/{id}", ScimUser.class, id);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<ScimUser> retrieveAll() {
        return restTemplate.getForObject(baseUrl + "/Users", List.class);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<ScimUser> query(String filter) {
        return restTemplate.getForObject(baseUrl + "/Users?filter={filter}", List.class, filter);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<ScimUser> query(String filter, String sortBy, boolean ascending) {
        String order = ascending ? "" : "&sortOrder=descending";
        return restTemplate.getForObject(baseUrl + "/Users?filter={filter}&sortBy={sortBy}" + order, List.class,
                        filter, sortBy);
    }

    @Override
    public ScimUser create(ScimUser user) {
        return restTemplate.postForObject(baseUrl + "/User", user, ScimUser.class);
    }

    @Override
    public ScimUser createUser(ScimUser user, String password) throws InvalidPasswordException,
                    InvalidScimResourceException {
        user.setPassword(password);
        return create(user);
    }

    @Override
    public ScimUser update(String id, ScimUser user) throws InvalidScimResourceException, ScimResourceNotFoundException {
        restTemplate.put(baseUrl + "/User/{id}", user, id);
        return user;
    }

    @Override
    public void changePassword(String id, String oldPassword, String newPassword)
                    throws ScimResourceNotFoundException {
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(oldPassword);
        request.setPassword(newPassword);
        restTemplate.put(baseUrl + "/User/{id}/password", request, id);
    }

    @Override
    public void updatePasswordChangeRequired(String userId, boolean passwordChangeRequired) throws ScimResourceNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ScimUser verifyUser(String id, int version) throws ScimResourceNotFoundException,
                    InvalidScimResourceException {
        HttpHeaders headers = new HttpHeaders();
        headers.set("If-Match", String.format("%d", version));
        return restTemplate.exchange(baseUrl + "/User/{id}/verify", HttpMethod.GET, new HttpEntity<Void>(headers),
                        ScimUser.class, id).getBody();
    }

    @Override
    public boolean checkPasswordMatches(String id, String password) throws ScimResourceNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean checkPasswordChangeIndividuallyRequired(String id) throws ScimResourceNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void updateLastLogonTime(String id) {

    }

    @Override
    public ScimUser delete(String id, int version) throws ScimResourceNotFoundException {
        HttpHeaders headers = new HttpHeaders();
        headers.set("If-Match", String.format("%d", version));
        return restTemplate.exchange(baseUrl + "/User/{id}", HttpMethod.DELETE, new HttpEntity<Void>(headers),
                        ScimUser.class, id).getBody();
    }

    @Override
    public int delete(String filter) {
        throw new UnsupportedOperationException();
    }
}
