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

/**
 * Useful X500 constants and utilities.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X500 {
    private X500() {}

    // RFC 4514 attribute type strings

    public static final String OID_CN       = "2.5.4.3";
    public static final String OID_C        = "2.5.4.6";
    public static final String OID_L        = "2.5.4.7";
    public static final String OID_ST       = "2.5.4.8";
    public static final String OID_STREET   = "2.5.4.9";
    public static final String OID_O        = "2.5.4.10";
    public static final String OID_OU       = "2.5.4.11";

    public static final String OID_UID      = "0.9.2342.19200300.100.1.1";
    public static final String OID_DC       = "0.9.2342.19200300.100.1.25";
}
