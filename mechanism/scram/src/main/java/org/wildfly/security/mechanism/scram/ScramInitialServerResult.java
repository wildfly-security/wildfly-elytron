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

package org.wildfly.security.mechanism.scram;

import org.wildfly.security.password.interfaces.ScramDigestPassword;

/**
 * A class for encapsulation of the initial SCRAM challenge and the digest password.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ScramInitialServerResult {
    private final ScramInitialServerMessage scramInitialChallenge;
    private final ScramDigestPassword scramDigestPassword;

    /**
     * Constructs a new {@code ScramInitialServerResult}.
     *
     * @param scramInitialChallenge the SCRAM challenge message.
     * @param scramDigestPassword the digest password for the SCRAM authentication.
     */
    ScramInitialServerResult(final ScramInitialServerMessage scramInitialChallenge, final ScramDigestPassword scramDigestPassword) {
        this.scramInitialChallenge = scramInitialChallenge;
        this.scramDigestPassword = scramDigestPassword;
    }

    /**
     * Returns the SCRAM challenge message.
     *
     * @return ScramInitialServerMessage
     */
    public ScramInitialServerMessage getScramInitialChallenge() {
        return scramInitialChallenge;
    }

    /**
     * Returns the digest password for the SCRAM authentication.
     *
     * @return ScramDigestPassword
     */
    public ScramDigestPassword getScramDigestPassword() {
        return scramDigestPassword;
    }
}
