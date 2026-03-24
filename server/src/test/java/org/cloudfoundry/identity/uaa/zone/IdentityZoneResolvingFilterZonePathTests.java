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
package org.cloudfoundry.identity.uaa.zone;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link IdentityZoneResolvingFilter} covering both hostname-based and path-based
 * (/z/{subdomain}/) zone resolution, plus all error cases (400, 404, 500, static resources).
 */
@EnabledIfZonePathsEnabled
class IdentityZoneResolvingFilterZonePathTests {

    private IdentityZoneProvisioning dao;
    private IdentityZoneResolvingFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private AtomicBoolean chainInvoked;
    private AtomicReference<IdentityZone> zoneInHolderWhenChainInvoked;

    private static final String ROOT_HOST = "uaa.mycf.com";

    @BeforeEach
    void setUp() {
        dao = mock(IdentityZoneProvisioning.class);
        filter = new IdentityZoneResolvingFilter(dao);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chainInvoked = new AtomicBoolean(false);
        zoneInHolderWhenChainInvoked = new AtomicReference<>();
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    private FilterChain chainThatCapturesHolder() {
        return (req, res) -> {
            chainInvoked.set(true);
            zoneInHolderWhenChainInvoked.set(IdentityZoneHolder.get());
        };
    }

    // ---------- Path-based: zone from request attribute ----------

    @Nested
    class PathBasedFromAttribute {

        @Test
        void zoneFound_fromAttribute_continuesChainWithZoneSet() throws Exception {
            request.setAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH, "myzone");
            request.setServerName("localhost"); // no host subdomain
            IdentityZone zone = MultitenancyFixture.identityZone("zone-id", "myzone");
            when(dao.retrieveBySubdomain(eq("myzone"))).thenReturn(zone);

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
            assertThat(chainInvoked.get()).isTrue();
            assertThat(zoneInHolderWhenChainInvoked.get()).isNotNull();
            assertThat(zoneInHolderWhenChainInvoked.get().getSubdomain()).isEqualTo("myzone");
        }

        @Test
        void zoneNotFound_fromAttribute_returns404AndSetsErrorCode() throws Exception {
            request.setAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH, "nonexistent");
            request.setServerName("localhost");
            when(dao.retrieveBySubdomain(eq("nonexistent"))).thenThrow(new EmptyResultDataAccessException(1));

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_NOT_FOUND);
            assertThat(request.getAttribute("error_message_code")).isEqualTo("zone.not.found");
            assertThat(chainInvoked.get()).isFalse();
        }

        @Test
        void staticResource_fromAttribute_zoneNotFound_continuesChain() throws Exception {
            request.setAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH, "nonexistent");
            request.setServerName("localhost");
            request.setContextPath("");
            request.setRequestURI("/resources/css/app.css");
            request.setServletPath("/resources/css/app.css");
            when(dao.retrieveBySubdomain(eq("nonexistent"))).thenThrow(new EmptyResultDataAccessException(1));

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
            assertThat(chainInvoked.get()).isTrue();
        }

        @Test
        void daoThrowsException_fromAttribute_returns500() throws Exception {
            request.setAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH, "myzone");
            request.setServerName("localhost");
            when(dao.retrieveBySubdomain(eq("myzone"))).thenThrow(new RuntimeException("db error"));

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            assertThat(response.getErrorMessage()).contains("Internal server error while fetching identity zone for subdomain myzone");
            assertThat(chainInvoked.get()).isFalse();
        }
    }

    // ---------- Path-based: zone from context path /z/{subdomain} ----------

    // ---------- Error: 400 when both path and host subdomain present ----------

    @Nested
    class BothPathAndHostSubdomain {

        @Test
        void pathSubdomainAndHostSubdomain_returns400() throws Exception {
            request.setAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH, "pathzone");
            request.setServerName("hostzone." + ROOT_HOST);
            filter.setDefaultInternalHostnames(Collections.singleton(ROOT_HOST));

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_BAD_REQUEST);
            assertThat(response.getErrorMessage()).isEqualTo("Cannot use both subdomain and zone path");
            assertThat(chainInvoked.get()).isFalse();
        }

        @Test
        void pathSubdomainAndDefaultZoneHost_continuesWithPathSubdomain() throws Exception {
            request.setAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH, "pathzone");
            request.setServerName(ROOT_HOST);
            filter.setDefaultInternalHostnames(Collections.singleton(ROOT_HOST));
            IdentityZone zone = MultitenancyFixture.identityZone("id", "pathzone");
            when(dao.retrieveBySubdomain(eq("pathzone"))).thenReturn(zone);

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
            assertThat(chainInvoked.get()).isTrue();
            assertThat(zoneInHolderWhenChainInvoked.get().getSubdomain()).isEqualTo("pathzone");
        }
    }

    // ---------- Hostname-based: zone resolution ----------

    @Nested
    class HostnameBased {

        @BeforeEach
        void setRootHost() {
            filter.setDefaultInternalHostnames(Collections.singleton(ROOT_HOST));
        }

        @Test
        void zoneFound_byHostSubdomain_continuesChainWithZoneSet() throws Exception {
            request.setServerName("myzone." + ROOT_HOST);
            IdentityZone zone = MultitenancyFixture.identityZone("zone-id", "myzone");
            when(dao.retrieveBySubdomain(eq("myzone"))).thenReturn(zone);

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
            assertThat(chainInvoked.get()).isTrue();
            assertThat(zoneInHolderWhenChainInvoked.get().getSubdomain()).isEqualTo("myzone");
        }

        @Test
        void defaultZone_byRootHost_continuesChainWithDefaultZone() throws Exception {
            request.setServerName(ROOT_HOST);
            IdentityZone uaaZone = IdentityZone.getUaa();
            when(dao.retrieveBySubdomain(eq(""))).thenReturn(uaaZone);

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(chainInvoked.get()).isTrue();
            assertThat(zoneInHolderWhenChainInvoked.get()).isEqualTo(uaaZone);
        }

        @Test
        void zoneNotFound_byHostSubdomain_returns404AndSetsErrorCode() throws Exception {
            request.setServerName("unknown." + ROOT_HOST);
            when(dao.retrieveBySubdomain(eq("unknown"))).thenThrow(new EmptyResultDataAccessException(1));

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_NOT_FOUND);
            assertThat(request.getAttribute("error_message_code")).isEqualTo("zone.not.found");
            assertThat(chainInvoked.get()).isFalse();
        }

        @Test
        void staticResource_zoneNotFound_byHost_continuesChain() throws Exception {
            request.setServerName("unknown." + ROOT_HOST);
            request.setContextPath("");
            request.setRequestURI("/vendor/font-awesome/css/font-awesome.min.css");
            request.setServletPath("/vendor/font-awesome/css/font-awesome.min.css");
            when(dao.retrieveBySubdomain(eq("unknown"))).thenThrow(new EmptyResultDataAccessException(1));

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
            assertThat(chainInvoked.get()).isTrue();
        }

        @Test
        void hostDoesNotMatchAnyRoot_returns404() throws Exception {
            request.setServerName("some.other.domain.com");
            // getSubdomain returns null; no DAO call for null subdomain

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_NOT_FOUND);
            assertThat(request.getAttribute("error_message_code")).isEqualTo("zone.not.found");
            assertThat(chainInvoked.get()).isFalse();
            verifyNoInteractions(dao);
        }

        @Test
        void daoThrowsException_byHostSubdomain_returns500() throws Exception {
            request.setServerName("myzone." + ROOT_HOST);
            when(dao.retrieveBySubdomain(eq("myzone"))).thenThrow(new RuntimeException("db error"));

            filter.doFilter(request, response, chainThatCapturesHolder());

            assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            assertThat(response.getErrorMessage()).contains("Internal server error while fetching identity zone for subdomain myzone");
            assertThat(chainInvoked.get()).isFalse();
        }
    }

    // ---------- Holder is cleared after chain ----------

    @Test
    void holderClearedAfterChain_byPath() throws Exception {
        request.setAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH, "myzone");
        request.setServerName("localhost");
        IdentityZone zone = MultitenancyFixture.identityZone("zone-id", "myzone");
        when(dao.retrieveBySubdomain(eq("myzone"))).thenReturn(zone);

        filter.doFilter(request, response, chainThatCapturesHolder());

        assertThat(IdentityZoneHolder.get()).isEqualTo(IdentityZone.getUaa());
    }

    @Test
    void holderClearedAfterChain_byHost() throws Exception {
        filter.setDefaultInternalHostnames(Collections.singleton(ROOT_HOST));
        request.setServerName("myzone." + ROOT_HOST);
        IdentityZone zone = MultitenancyFixture.identityZone("zone-id", "myzone");
        when(dao.retrieveBySubdomain(eq("myzone"))).thenReturn(zone);

        filter.doFilter(request, response, chainThatCapturesHolder());

        assertThat(IdentityZoneHolder.get()).isEqualTo(IdentityZone.getUaa());
    }
}
