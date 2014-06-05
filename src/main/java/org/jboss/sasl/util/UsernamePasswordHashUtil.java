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
package org.jboss.sasl.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @deprecated As of version 2, instead use {@link org.wildfly.sasl.util.UsernamePasswordHashUtil}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@Deprecated
public class UsernamePasswordHashUtil extends org.wildfly.sasl.util.UsernamePasswordHashUtil {

    public UsernamePasswordHashUtil() throws NoSuchAlgorithmException {
        super();
    }

    public UsernamePasswordHashUtil(final MessageDigest digest) {
        super(digest);
    }



}
