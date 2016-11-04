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

package org.wildfly.security.credential;

import org.ietf.jgss.GSSCredential;
import org.wildfly.common.Assert;

/**
 * A credential for holding a {@code GSSCredential}.
 */
public final class GSSCredentialCredential implements Credential {
    private final GSSCredential gssCredential;

    /**
     * Construct a new instance.
     *
     * @param gssCredential the GSS credential (may not be {@code null})
     */
    public GSSCredentialCredential(final GSSCredential gssCredential) {
        Assert.checkNotNullParam("gssCredential", gssCredential);
        this.gssCredential = gssCredential;
    }

    /**
     * Get the GSS credential.
     *
     * @return the GSS credential (not {@code null})
     */
    public GSSCredential getGssCredential() {
        return gssCredential;
    }

    public GSSCredentialCredential clone() {
        return this;
    }

}
