/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth;

import java.util.Map;

/**
 * A key for accessing an identity from an identity context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@SuppressWarnings("unchecked")
public class IdentityKey<I extends SecurityIdentity> {

    public final I getIdentity() {
        Map<IdentityKey<?>, SecurityIdentity> identityKeys = IdentityContext.captureCurrent().identityKeys;
        return identityKeys == null ? null : (I) identityKeys.get(this);
    }

    public final I getIdentity(I defaultValue) {
        Map<IdentityKey<?>, SecurityIdentity> identityKeys = IdentityContext.captureCurrent().identityKeys;
        if (identityKeys != null) {
            final I value = (I) identityKeys.get(this);
            if (value != null) {
                return value;
            }
        }
        return defaultValue;
    }

    public final I getIdentity(IdentityContext securityContext) {
        Map<IdentityKey<?>, SecurityIdentity> identityKeys = securityContext.identityKeys;
        return identityKeys == null ? null : (I) identityKeys.get(this);
    }

    public final I getIdentity(IdentityContext identityContext, I defaultValue) {
        Map<IdentityKey<?>, SecurityIdentity> identityKeys = identityContext.identityKeys;
        if (identityKeys != null) {
            final I value = (I) identityKeys.get(this);
            if (value != null) {
                return value;
            }
        }
        return defaultValue;
    }
}
