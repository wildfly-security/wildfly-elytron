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

package org.wildfly.security.authz;

/**
 * A realm's authorization identity.  Objects of this class represent an active identity which may be examined for
 * authorization decisions.  Since there is no upper bound in the lifespan of instances of this class, they should
 * not retain references to scarce resources like database connections or file handles.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface AuthorizationIdentity {

    /**
     * Get the attributes which pertain to this identity.  By default, an empty attribute collection is returned.
     *
     * @return the attributes
     */
    default Attributes getAttributes() {
        return Attributes.EMPTY;
    }

    /**
     * The empty authorization identity.
     */
    AuthorizationIdentity EMPTY = basicIdentity(Attributes.EMPTY);

    /**
     * Create a basic authorization identity implementation.
     *
     * @param attributes the identity attributes
     * @return the authorization identity
     */
    static AuthorizationIdentity basicIdentity(Attributes attributes) {
        return new AuthorizationIdentity() {

            public Attributes getAttributes() {
                return attributes;
            }
        };
    }
}
