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

import java.util.ArrayList;
import java.util.Map;

import org.wildfly.common.Assert;

/**
 * Representation of a realm access claim.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class RealmAccessClaim {
    public static final String ROLES = "roles";
    public static final String VERIFY_CALLER = "verify_caller";

    private final Map<String, Object> realmAccessClaim;

    /**
     * Construct a new instance.
     *
     * @param realmAccessClaim the realm access claim set for this instance (may not be {@code null})
     */
    public RealmAccessClaim(Map<String, Object> realmAccessClaim) {
        Assert.checkNotNullParam("addressClaimSet", realmAccessClaim);
        this.realmAccessClaim = realmAccessClaim;
    }

    public ArrayList<String> getRoles() {
        return (ArrayList<String>) realmAccessClaim.get(ROLES);
    }

    public Boolean getVerifyCaller() {
        return (Boolean) realmAccessClaim.get(VERIFY_CALLER);
    }

}
