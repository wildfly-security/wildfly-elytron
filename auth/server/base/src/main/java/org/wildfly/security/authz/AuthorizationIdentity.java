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

import java.util.function.Supplier;

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
     * @return the attributes (must not be {@code null})
     */
    default Attributes getAttributes() {
        return Attributes.EMPTY;
    }

    /**
     * Get the runtime attributes which pertain to this identity.  By default, an empty attribute collection is returned.
     *
     * @return the runtime attributes (must not be {@code null})
     */
    default Attributes getRuntimeAttributes() {
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
        return basicIdentity(() -> attributes, "EMPTY");
    }

    /**
     * Create a basic authorization identity implementation.
     *
     * @param attributes the identity attributes
     * @return the authorization identity
     */
    static AuthorizationIdentity basicIdentity(Supplier<Attributes> attributes, final String string) {
        return new AuthorizationIdentity() {

            public Attributes getAttributes() {
                return attributes.get();
            }

            @Override
            public String toString() {
                return string;
            }

        };
    }

    /**
     * Create a basic authorization identity implementation using the given attributes and runtime attributes.
     *
     * @param attributes the attributes
     * @param runtimeAttributes the runtime attributes
     * @return the authorization identity
     */
    static AuthorizationIdentity basicIdentity(Supplier<Attributes> attributes, Supplier<Attributes> runtimeAttributes, final String string) {
        return new AuthorizationIdentity() {

            public Attributes getAttributes() {
                return attributes.get();
            }

            public Attributes getRuntimeAttributes() {
                return runtimeAttributes.get();
            }

            @Override
            public String toString() {
                return string;
            }

        };
    }

    /**
     * Create a basic authorization identity implementation using the given authorization
     * identity and runtime attributes.
     *
     * @param authorizationIdentity the authorization identity
     * @param runtimeAttributes the identity runtime attributes
     * @return the authorization identity
     */
    static AuthorizationIdentity basicIdentity(AuthorizationIdentity authorizationIdentity, Attributes runtimeAttributes) {
        Attributes attributes = authorizationIdentity.getAttributes();
        Attributes combinedRuntimeAttributes = AggregateAttributes.aggregateOf(authorizationIdentity.getRuntimeAttributes(), runtimeAttributes);
        return basicIdentity(() -> attributes, () -> combinedRuntimeAttributes, "EMPTY");
    }

}
