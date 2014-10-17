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

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.wildfly.security.auth.principal.AnonymousPrincipal;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetAnonymousAuthenticationConfiguration extends AuthenticationConfiguration {

    private static final Set<String> ONLY_ANONYMOUS = Collections.singleton("ANONYMOUS");

    SetAnonymousAuthenticationConfiguration(final AuthenticationConfiguration parent) {
        super(parent.without(SetCallbackHandlerAuthenticationConfiguration.class).without(SetNamePrincipalAuthenticationConfiguration.class));
    }

    void filterSaslMechanisms(final Collection<String> names) {
        // apparently no principal has been set; we only allow anonymous
        names.retainAll(ONLY_ANONYMOUS);
        super.filterSaslMechanisms(names);
    }

    Principal getPrincipal() {
        return AnonymousPrincipal.getInstance();
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetAnonymousAuthenticationConfiguration(newParent);
    }
}
