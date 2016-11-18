/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.password.spec;

import java.io.Serializable;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

/**
 * A {@link AlgorithmParameterSpec} for a password represented by digesting it with a username and realm as defined by RFC2617 and
 * RFC2831.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class DigestPasswordAlgorithmSpec implements AlgorithmParameterSpec, Serializable  {

    private static final long serialVersionUID = 4925821569951433413L;

    private final String username;
    private final String realm;

    public DigestPasswordAlgorithmSpec(String username, String realm) {
        this.username = username;
        this.realm = realm;
    }

    public String getUsername() {
        return username;
    }

    public String getRealm() {
        return realm;
    }

    public boolean equals(Object other) {
        if (! (other instanceof DigestPasswordAlgorithmSpec)) return false;
        if (this == other) return true;
        DigestPasswordAlgorithmSpec otherSpec = (DigestPasswordAlgorithmSpec) other;
        return Objects.equals(username, otherSpec.username) && Objects.equals(realm, otherSpec.realm);
    }

    public int hashCode() {
        return Objects.hashCode(username) * 31 + Objects.hashCode(realm);
    }
}
