/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.callback;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.SecurityRealm;

/**
 * A callback used to query a server participant for the names of realms that it is prepared to offer.  Note that the
 * SASL realm concept is not directly related to the Elytron {@linkplain SecurityRealm security realm concept}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AvailableRealmsCallback implements ExtendedCallback {
    private String[] realmNames;

    /**
     * Construct a new instance.
     */
    public AvailableRealmsCallback() {
    }

    /**
     * Get the array of realm names that was set.
     *
     * @return the realm names array
     */
    public String[] getRealmNames() {
        return realmNames;
    }

    /**
     * Set the realm names.  None of the realm names may be {@code null}.  The array is not copied, so care must
     * be taken to avoid modifying the realm array after it is set.
     *
     * @param realmNames the realm names (may not be {@code null}, may not contain {@code null})
     */
    public void setRealmNames(final String... realmNames) {
        Assert.checkNotNullParam("realmNames", realmNames);
        for (int i = 0, realmNamesLength = realmNames.length; i < realmNamesLength; i++) {
            Assert.checkNotNullArrayParam("realmNames", i, realmNames[i]);
        }
        this.realmNames = realmNames;
    }

    public boolean isOptional() {
        return true;
    }

    public boolean needsInformation() {
        return true;
    }
}
