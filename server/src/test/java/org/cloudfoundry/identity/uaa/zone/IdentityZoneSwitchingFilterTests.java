/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.web.HttpHeadersFilterRequestWrapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdentityZoneSwitchingFilterTests {

    @Test
    void stripPrefix() {
        String zoneId = new RandomValueStringGenerator().generate();
        IdentityZoneSwitchingFilter filter = new IdentityZoneSwitchingFilter(mock(IdentityZoneProvisioning.class));
        assertThat(filter.stripPrefix("zones." + zoneId + ".admin", zoneId)).isEqualTo("zones." + zoneId + ".admin");
        assertThat(filter.stripPrefix("zones." + zoneId + ".read", zoneId)).isEqualTo("zones." + zoneId + ".read");
        assertThat(filter.stripPrefix("zones." + zoneId + ".clients.admin", zoneId)).isEqualTo("clients.admin");
        assertThat(filter.stripPrefix("zones." + zoneId + ".clients.read", zoneId)).isEqualTo("clients.read");
        assertThat(filter.stripPrefix("zones." + zoneId + ".idps.read", zoneId)).isEqualTo("idps.read");
    }

    @Test
    void headerRemovedIfSwitchingToUaaZone() throws Exception {
        IdentityZoneProvisioning zoneProvisioning = mock(IdentityZoneProvisioning.class);
        when(zoneProvisioning.retrieve(anyString())).thenReturn(IdentityZone.getUaa());
        IdentityZoneSwitchingFilter filter = new IdentityZoneSwitchingFilter(zoneProvisioning);

        FilterChain chain = mock(FilterChain.class);
        ArgumentCaptor<HttpServletRequest> requestArgumentCaptor = ArgumentCaptor.forClass(HttpServletRequest.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(HEADER)).thenReturn(IdentityZone.getUaaZoneId());

        filter.doFilterInternal(request, null, chain);
        verify(chain).doFilter(requestArgumentCaptor.capture(), any());

        HttpServletRequest modifiedRequest = requestArgumentCaptor.getValue();
        assertThat(modifiedRequest).isInstanceOf(HttpHeadersFilterRequestWrapper.class);
        assertThat(modifiedRequest.getHeader(HEADER)).isNull();
    }

}