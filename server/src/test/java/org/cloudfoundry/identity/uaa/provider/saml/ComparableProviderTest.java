package org.cloudfoundry.identity.uaa.provider.saml;
/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ComparableProviderTest {

    static class ComparableProviderImpl implements ComparableProvider {
        private String alias;
        private String zoneId;

        @Override
        public String getAlias() {
            return alias;
        }

        @Override
        public String getZoneId() {
            return zoneId;
        }

        @Override
        public byte[] fetchMetadata() {
            return new byte[0];
        }

        public ComparableProviderImpl setAlias(String alias) {
            this.alias = alias;
            return this;
        }

        public ComparableProviderImpl setZoneId(String zoneId) {
            this.zoneId = zoneId;
            return this;
        }

    }

    @Test
    public void testCompareTo() {
        ComparableProviderImpl comparableProviderThis = new ComparableProviderImpl();
        ComparableProviderImpl comparableProviderThat = new ComparableProviderImpl();

        comparableProviderThis.setAlias(null).setZoneId(null);
        comparableProviderThat.setAlias("alias").setZoneId("zone");
        assertThat(comparableProviderThis).isLessThan(comparableProviderThat);

        comparableProviderThat.setAlias("alias").setZoneId(null);
        assertThat(comparableProviderThis).isLessThan(comparableProviderThat);

        comparableProviderThat.setAlias(null).setZoneId("zone");
        assertThat(comparableProviderThis).isLessThan(comparableProviderThat);

        comparableProviderThat.setAlias(null).setZoneId(null);
        assertThat(comparableProviderThis).isEqualByComparingTo(comparableProviderThat);

        comparableProviderThis.setAlias(null).setZoneId("zone");
        comparableProviderThat.setAlias("alias").setZoneId("zone");
        assertThat(comparableProviderThis).isLessThan(comparableProviderThat);

        comparableProviderThat.setAlias("alias").setZoneId(null);
        assertThat(comparableProviderThis).isLessThan(comparableProviderThat);

        comparableProviderThat.setAlias(null).setZoneId("zone");
        assertThat(comparableProviderThis).isEqualByComparingTo(comparableProviderThat);

        comparableProviderThat.setAlias(null).setZoneId(null);
        assertThat(comparableProviderThis).isGreaterThan(comparableProviderThat);


        comparableProviderThis.setAlias("alias").setZoneId(null);
        comparableProviderThat.setAlias("alias").setZoneId("zone");
        assertThat(comparableProviderThis).isLessThan(comparableProviderThat);

        comparableProviderThat.setAlias("alias").setZoneId(null);
        assertThat(comparableProviderThis).isEqualByComparingTo(comparableProviderThat);

        comparableProviderThat.setAlias(null).setZoneId("zone");
        assertThat(comparableProviderThis).isGreaterThan(comparableProviderThat);

        comparableProviderThat.setAlias(null).setZoneId(null);
        assertThat(comparableProviderThis).isGreaterThan(comparableProviderThat);

        comparableProviderThis.setAlias("alias").setZoneId("zone");
        comparableProviderThat.setAlias("alias").setZoneId("zone");
        assertThat(comparableProviderThis).isEqualByComparingTo(comparableProviderThat);

        comparableProviderThat.setAlias("alias").setZoneId(null);
        assertThat(comparableProviderThis).isGreaterThan(comparableProviderThat);

        comparableProviderThat.setAlias(null).setZoneId("zone");
        assertThat(comparableProviderThis).isGreaterThan(comparableProviderThat);

        comparableProviderThat.setAlias(null).setZoneId(null);
        assertThat(comparableProviderThis).isGreaterThan(comparableProviderThat);
    }

    @Test
    public void testGetHashCode() {
        ComparableProviderImpl comparableProvider1 = new ComparableProviderImpl();
        ComparableProviderImpl comparableProvider2 = new ComparableProviderImpl();
        comparableProvider1.setAlias(null).setZoneId(null);

        assertThat(comparableProvider1.getHashCode()).isZero();

        comparableProvider1.setAlias(null).setZoneId("zone");
        comparableProvider2.setAlias(null).setZoneId("zone");
        assertThat(comparableProvider2.getHashCode()).isEqualTo(comparableProvider1.getHashCode());

        comparableProvider1.setAlias("alias").setZoneId(null);
        comparableProvider2.setAlias("alias").setZoneId(null);
        assertThat(comparableProvider2.getHashCode()).isEqualTo(comparableProvider1.getHashCode());

        comparableProvider1.setAlias("alias").setZoneId(null);
        comparableProvider2.setAlias(null).setZoneId("zone");
        assertThat(comparableProvider2.getHashCode()).isNotEqualTo(comparableProvider1.getHashCode());
    }
}