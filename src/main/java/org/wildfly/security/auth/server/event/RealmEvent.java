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

package org.wildfly.security.auth.server.event;

/**
 * An event which is potentially relevant to a realm.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class RealmEvent {

    /**
     * Construct a new instance.
     */
    protected RealmEvent() {
    }

    /**
     * Accept the given visitor, calling the method which is most applicable to this event type.
     *
     * @param visitor the visitor
     * @param param the parameter to pass to the visitor {@code handleXxx} method
     * @param <P> the visitor parameter type
     * @param <R> the visitor return type
     * @return the value returned from the visitor {@code handleXxx} method
     */
    public <P, R> R accept(RealmEventVisitor<P, R> visitor, P param) {
        return visitor.handleUnknownEvent(this, param);
    }
}
