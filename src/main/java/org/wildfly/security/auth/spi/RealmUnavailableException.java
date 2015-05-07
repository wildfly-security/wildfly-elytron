/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.auth.spi;

import java.security.GeneralSecurityException;

/**
 * An exception to indicate a general underlying failure of the realm.
 *
 * Realms should only make use of this exception for general failures within the realm such as being unable to communicate with
 * a remote store of users rather than to report errors with a specific authentication request.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class RealmUnavailableException extends GeneralSecurityException {

    private static final long serialVersionUID = 5893125522523952643L;

    public RealmUnavailableException() {
        super();
    }

    public RealmUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public RealmUnavailableException(String message) {
        super(message);
    }

    public RealmUnavailableException(Throwable cause) {
        super(cause);
    }

}
