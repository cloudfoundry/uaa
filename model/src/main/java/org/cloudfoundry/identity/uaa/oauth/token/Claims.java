/*
 * ******************************************************************************
 *       Cloud Foundry Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *       This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *       You may not use this product except in compliance with the License.
 *
 *       This product includes a number of subcomponents with
 *       separate copyright notices and license terms. Your use of these
 *       subcomponents is subject to the terms and conditions of the
 *       subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Claims {

    @JsonProperty(ClaimConstants.USER_ID)
    private String userId;
    @JsonProperty(ClaimConstants.USER_NAME)
    private String userName;
    @JsonProperty(ClaimConstants.NAME)
    private String name;
    @JsonProperty(ClaimConstants.GIVEN_NAME)
    private String givenName;
    @JsonProperty(ClaimConstants.FAMILY_NAME)
    private String familyName;
    @JsonProperty(ClaimConstants.PHONE_NUMBER)
    private String phoneNumber;
    @JsonProperty(ClaimConstants.EMAIL)
    private String email;
    @JsonProperty(ClaimConstants.CLIENT_ID)
    private String clientId;
    @JsonProperty(ClaimConstants.EXPIRY_IN_SECONDS)
    private Long exp;
    @JsonProperty(ClaimConstants.AUTHORITIES)
    private List<String> authorities;
    @JsonProperty(ClaimConstants.SCOPE)
    private List<String> scope;
    @JsonProperty(ClaimConstants.GRANTED_SCOPES)
    private List<String> grantedScopes;
    @JsonProperty(ClaimConstants.JTI)
    private String jti;
    @JsonProperty(ClaimConstants.AUD)
    private List<String> aud;
    @JsonProperty(ClaimConstants.SUB)
    private String sub;
    @JsonProperty(ClaimConstants.ISS)
    private String iss;
    @JsonProperty(ClaimConstants.IAT)
    private Integer iat;
    @JsonProperty(ClaimConstants.CID)
    private String cid;
    @JsonProperty(ClaimConstants.GRANT_TYPE)
    private String grantType;
    @JsonProperty(ClaimConstants.ADDITIONAL_AZ_ATTR)
    private Map<String, String> azAttr;
    @JsonProperty(ClaimConstants.AZP)
    private String azp;
    @JsonProperty(ClaimConstants.AUTH_TIME)
    private Long authTime;
    @JsonProperty(ClaimConstants.ZONE_ID)
    private String zid;
    @JsonProperty(ClaimConstants.REVOCATION_SIGNATURE)
    private String revSig;
    @JsonProperty(ClaimConstants.NONCE)
    private String nonce;
    @JsonProperty(ClaimConstants.ORIGIN)
    private String origin;
    @JsonProperty(ClaimConstants.ROLES)
    private String roles;
    @JsonProperty(ClaimConstants.PROFILE)
    private String profile;
    @JsonProperty(ClaimConstants.USER_ATTRIBUTES)
    private String userAttributes;
    @JsonProperty(ClaimConstants.REVOCABLE)
    private boolean revocable;
    @JsonProperty(ClaimConstants.EXTERNAL_ATTR)
    private Map<String, String> extAttr;
    @JsonProperty(ClaimConstants.PREVIOUS_LOGON_TIME)
    private Long previousLogonTime;
    @JsonProperty(ClaimConstants.AMR)
    private String[] amr;
    @JsonProperty(ClaimConstants.CLIENT_AUTH_METHOD)
    private String clientAuth;
    @JsonProperty(ClaimConstants.ACT)
    private Map<String, Object> actorClaims;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public List<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    public List<String> getScope() {
        return scope;
    }

    public void setScope(List<String> scope) {
        this.scope = scope;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public List<String> getAud() {
        return aud;
    }

    public void setAud(List<String> aud) {
        this.aud = aud;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public Integer getIat() {
        return iat;
    }

    public void setIat(Integer iat) {
        this.iat = iat;
    }

    public String getCid() {
        return cid;
    }

    public void setCid(String cid) {
        this.cid = cid;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public Map<String, String> getAzAttr() {
        return azAttr;
    }

    public void setAzAttr(Map<String, String> azAttr) {
        this.azAttr = azAttr;
    }

    public String getAzp() {
        return azp;
    }

    public void setAzp(String azp) {
        this.azp = azp;
    }

    public Long getAuthTime() {
        return authTime;
    }

    public void setAuthTime(Long authTime) {
        this.authTime = authTime;
    }

    public String getZid() {
        return zid;
    }

    public void setZid(String zid) {
        this.zid = zid;
    }

    public String getRevSig() {
        return revSig;
    }

    public void setRevSig(String revSig) {
        this.revSig = revSig;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getUserAttributes() {
        return userAttributes;
    }

    public void setUserAttributes(String userAttributes) {
        this.userAttributes = userAttributes;
    }

    public boolean isRevocable() {
        return revocable;
    }

    public void setRevocable(boolean revocable) {
        this.revocable = revocable;
    }

    public Map<String, String> getExtAttr() {
        return extAttr;
    }

    public void setExtAttr(Map<String, String> extAttr) {
        this.extAttr = extAttr;
    }

    public Long getPreviousLogonTime() {
        return previousLogonTime;
    }

    public void setPreviousLogonTime(Long previousLogonTime) {
        this.previousLogonTime = previousLogonTime;
    }

    public String[] getAmr() {
        return amr;
    }

    public void setAmr(String[] amr) {
        this.amr = amr;
    }

    public List<String> getGrantedScopes() {
        return grantedScopes;
    }

    public void setGrantedScopes(List<String> grantedScopes) {
        this.grantedScopes = grantedScopes;
    }

    public String getClientAuth() {
        return this.clientAuth;
    }

    public void setClientAuth(final String clientAuth) {
        this.clientAuth = clientAuth;
    }

    public Map<String, Object> getActorClaims() {
        return this.actorClaims;
    }

    @JsonIgnore
    public Map<String, Object> getClaimMap() {
        return JsonUtils.convertValue(this, HashMap.class);
    }
}
