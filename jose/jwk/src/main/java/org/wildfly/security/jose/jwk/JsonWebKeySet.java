/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.jose.jwk;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A class that represents a JSON Web Key set.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.14.0
 */
public class JsonWebKeySet {

    @JsonProperty("keys")
    private JWK[] keys;

    public JWK[] getKeys() {
        return keys;
    }

    public void setKeys(JWK[] keys) {
        this.keys = keys;
    }
}
