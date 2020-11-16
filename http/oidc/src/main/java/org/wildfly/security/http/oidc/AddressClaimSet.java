/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import java.util.Map;

import org.wildfly.common.Assert;

/**
 * Representation of an address claim as per <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class AddressClaimSet {
    public static final String FORMATTED = "formatted";
    public static final String STREET_ADDRESS = "street_address";
    public static final String LOCALITY = "locality";
    public static final String REGION = "region";
    public static final String POSTAL_CODE = "postal_code";
    public static final String COUNTRY = "country";

    private final Map<String, String> addressClaimSet;

    /**
     * Construct a new instance.
     *
     * @param addressClaimSet the address claim set for this instance (may not be {@code null})
     */
    public AddressClaimSet(Map<String, String> addressClaimSet) {
        Assert.checkNotNullParam("addressClaimSet", addressClaimSet);
        this.addressClaimSet = addressClaimSet;
    }

    public String getFormattedAddress() {
        return addressClaimSet.get(FORMATTED);
    }

    public String getStreetAddress() {
        return addressClaimSet.get(STREET_ADDRESS);
    }

    public String getLocality() {
        return addressClaimSet.get(LOCALITY);
    }

    public String getRegion() {
        return addressClaimSet.get(REGION);
    }

    public String getPostalCode() {
        return addressClaimSet.get(POSTAL_CODE);
    }

    public String getCountry() {
        return addressClaimSet.get(COUNTRY);
    }
}
