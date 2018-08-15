/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert.acme;

/**
 * The various <a href="https://www.ietf.org/id/draft-ietf-acme-acme-14.txt">Automatic Certificate Management
 * Environment (ACME)</a> protocol resource types.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.5.0
 */
public enum AcmeResource {
    NEW_NONCE("newNonce"),
    NEW_ACCOUNT("newAccount"),
    NEW_ORDER("newOrder"),
    NEW_AUTHZ("newAuthz"),
    REVOKE_CERT("revokeCert"),
    KEY_CHANGE("keyChange");

    private final String name;

    AcmeResource(String name) {
        this.name = name;
    }

    /**
     * Get the string value of this resource type.
     *
     * @return the string value of this resource type
     */
    public String getValue() {
        return name;
    }

}
