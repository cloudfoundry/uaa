/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.uaa.scim;

import java.util.List;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * Remote implementation of {@link ScimUserProvisioning} using the Scim endpoints on a remote server.
 * 
 * @author Dave Syer
 * 
 */
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
	public ScimUser retrieveUser(String id) throws ScimResourceNotFoundException {
		return restTemplate.getForObject(baseUrl + "/User/{id}", ScimUser.class, id);
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<ScimUser> retrieveUsers() {
		return restTemplate.getForObject(baseUrl + "/Users", List.class);
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public List<ScimUser> retrieveUsers(String filter) {
		return restTemplate.getForObject(baseUrl + "/Users?filter={filter}", List.class, filter);
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<ScimUser> retrieveUsers(String filter, String sortBy, boolean ascending) {
		String order = ascending ? "" : "&sortOrder=descending";
		return restTemplate.getForObject(baseUrl + "/Users?filter={filter}&sortBy={sortBy}" + order, List.class, filter, sortBy);
	}

	@Override
	public ScimUser createUser(ScimUser user, String password) throws InvalidPasswordException, InvalidScimResourceException {
		user.setPassword(password);
		return restTemplate.postForObject(baseUrl + "/User", user, ScimUser.class);
	}

	@Override
	public ScimUser updateUser(String id, ScimUser user) throws InvalidScimResourceException, ScimResourceNotFoundException {
		restTemplate.put(baseUrl + "/User/{id}", user, id);
		return user;
	}

	@Override
	public boolean changePassword(String id, String oldPassword, String newPassword) throws ScimResourceNotFoundException {
		PasswordChangeRequest request = new PasswordChangeRequest();
		request.setOldPassword(oldPassword);
		request.setPassword(newPassword);
		restTemplate.put(baseUrl + "/User/{id}/password", request, id);
		return true;
	}

	@Override
	public ScimUser removeUser(String id, int version) throws ScimResourceNotFoundException {
		HttpHeaders headers = new HttpHeaders();
		headers.set("If-Match", String.format("%d", version));
		return restTemplate.exchange(baseUrl + "/User/{id}", HttpMethod.DELETE, new HttpEntity<Void>(headers), ScimUser.class, id).getBody();
	}
}
