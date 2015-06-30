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

package org.wildfly.security.x500;

import java.security.Principal;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.auth.util.PrincipalDecoder;

/**
 * A principal decoder which extracts the "common name" (CN) attribute from the principal.  The first CN of the
 * certificate is used.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X500CommonNamePrincipalDecoder implements PrincipalDecoder {
    private static final X500CommonNamePrincipalDecoder INSTANCE = new X500CommonNamePrincipalDecoder();

    private X500CommonNamePrincipalDecoder() {
    }

    /**
     * Get the decoder instance.
     *
     * @return the decoder instance (not {@code null})
     */
    public static X500CommonNamePrincipalDecoder getInstance() {
        return INSTANCE;
    }

    public String getName(final Principal principal) {
        final X500Principal x500Principal = X500PrincipalUtil.asX500Principal(principal);
        if (x500Principal == null) {
            return null;
        }
        final String[] values = X500PrincipalUtil.getAttributeValues(x500Principal, X500.OID_CN);
        if (values.length == 0) {
            return null;
        } else {
            return values[0];
        }
    }
}
