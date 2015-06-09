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

package org.wildfly.security.auth.principal;

import sun.security.x509.X500Name;

import java.security.Principal;

import javax.security.auth.x500.X500Principal;

/**
 * A set of utilities for {@code Principal} instances.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PrincipalUtil {

    private static final boolean HAS_X500_NAME;

    static {
        boolean hasX500Name = false;
        try {
            Class.forName("sun.security.x509.X500Name", true, PrincipalUtil.class.getClassLoader());
            hasX500Name = true;
        } catch (Throwable t) {}
        HAS_X500_NAME = hasX500Name;
    }

    /**
     * Attempt to convert the given principal to an X.500 principal.
     *
     * @param principal the original principal
     * @return the X.500 principal
     */
    public static X500Principal asX500Principal(Principal principal) {
        if (principal instanceof X500Principal) {
            return (X500Principal) principal;
        }
        if (HAS_X500_NAME && principal instanceof X500Name) {
            return ((X500Name) principal).asX500Principal();
        }
        // if all else fails...
        return new X500Principal(principal.getName());
    }
}
