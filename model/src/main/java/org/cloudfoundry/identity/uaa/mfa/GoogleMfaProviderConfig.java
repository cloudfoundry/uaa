/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mfa;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class GoogleMfaProviderConfig extends AbstractMfaProviderConfig {

    public enum Algorithm {
        SHA256,
        SHA512;

        private static Map<String, GoogleMfaProviderConfig.Algorithm> namesMap = new HashMap();
        static {
            namesMap.put("SHA256", SHA256);
            namesMap.put("SHA512", SHA512);
        }

        @JsonCreator
        public static GoogleMfaProviderConfig.Algorithm forValue(String value) {
            return namesMap.get(value);
        }

        public static Set<String> getStringValues() {
            return namesMap.keySet();
        }

    }

    private String providerDescription;
    private int digits = 6;
    private int duration = 30;
    private Algorithm algorithm = Algorithm.SHA256;


    public void validate() {}

    public String getProviderDescription() {
        return providerDescription;
    }

    public GoogleMfaProviderConfig setProviderDescription(String providerDescription) {
        this.providerDescription = providerDescription;
        return this;
    }

    public int getDigits() {
        return digits;
    }

    public GoogleMfaProviderConfig setDigits(int digits) {
        this.digits = digits;
        return this;
    }

    public int getDuration() {
        return duration;
    }

    public GoogleMfaProviderConfig setDuration(int duration) {
        this.duration = duration;
        return this;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public GoogleMfaProviderConfig setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GoogleMfaProviderConfig that = (GoogleMfaProviderConfig) o;

        if (digits != that.digits) return false;
        if (duration != that.duration) return false;
        if (providerDescription != null ? !providerDescription.equals(that.providerDescription) : that.providerDescription != null)
            return false;
        if(algorithm != that.algorithm) return false;
        return super.equals(that);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result += providerDescription != null ? providerDescription.hashCode() : 0;
        result = 31 * result + digits;
        result = 31 * result + duration;
        result = 31 * result + (algorithm != null ? algorithm.hashCode() : 0);
        return result;
    }
}