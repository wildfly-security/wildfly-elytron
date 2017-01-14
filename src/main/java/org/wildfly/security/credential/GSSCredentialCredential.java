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

import javax.security.auth.kerberos.KerberosTicket;

import org.ietf.jgss.GSSCredential;
import org.wildfly.common.Assert;

/**
 * A credential for holding a {@code GSSCredential} and optionally an associated {@link KerberosTicket}.
 */
public final class GSSCredentialCredential implements Credential {
    private final GSSCredential gssCredential;
    private final KerberosTicket kerberosTicket;

    /**
     * Construct a new instance.
     *
     * @param gssCredential the GSS credential (may not be {@code null})
     */
    public GSSCredentialCredential(final GSSCredential gssCredential) {
        this(gssCredential, null);
    }

    /**
     * Construct a new instance.
     *
     * @param gssCredential the GSS credential (may not be {@code null})
     * @param kerberosTicket the associated Kerberos ticket which may be {@code null}.
     */
    public GSSCredentialCredential(final GSSCredential gssCredential, final KerberosTicket kerberosTicket) {
        Assert.checkNotNullParam("gssCredential", gssCredential);
        this.gssCredential = gssCredential;
        this.kerberosTicket = kerberosTicket;
    }

    /**
     * Get the GSS credential.
     *
     * @return the GSS credential (not {@code null})
     */
    public GSSCredential getGssCredential() {
        return gssCredential;
    }

    /**
     * Get the associated kerberos ticket.
     *
     * @return the associated kerberos ticker or {@code null} if one is not associated.
     */
    public KerberosTicket getKerberosTicket() {
        return kerberosTicket;
    }

    public GSSCredentialCredential clone() {
        return this;
    }

}
