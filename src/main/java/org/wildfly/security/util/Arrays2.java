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

package org.wildfly.security.util;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class Arrays2 {

    private Arrays2() {
    }

    public static boolean equals(byte[] a1, int offs1, byte[] a2, int offs2, int len) {
        if (offs1 + len > a1.length) return false;
        if (offs2 + len > a2.length) return false;
        for (int i = 0; i < len; i ++) {
            if (a1[i + offs1] != a2[i + offs2]) {
                return false;
            }
        }
        return true;
    }

    public static boolean equals(byte[] a1, int offs1, byte[] a2) {
        return equals(a1, offs1, a2, 0, a2.length);
    }

    public static boolean equals(char[] a1, int offs1, char[] a2, int offs2, int len) {
        if (offs1 + len > a1.length) return false;
        if (offs2 + len > a2.length) return false;
        for (int i = 0; i < len; i ++) {
            if (a1[i + offs1] != a2[i + offs2]) {
                return false;
            }
        }
        return true;
    }

    public static boolean equals(char[] a1, int offs1, char[] a2) {
        return equals(a1, offs1, a2, 0, a2.length);
    }

    public static boolean equals(char[] a1, int offs1, String a2, int offs2, int len) {
        if (offs1 + len > a1.length) return false;
        if (offs2 + len > a2.length()) return false;
        for (int i = 0; i < len; i ++) {
            if (a1[i + offs1] != a2.charAt(i + offs2)) {
                return false;
            }
        }
        return true;
    }

    public static boolean equals(char[] a1, int offs1, String a2) {
        return equals(a1, offs1, a2, 0, a2.length());
    }

    public static boolean equals(String a1, int offs1, char[] a2) {
        return equals(a2, 0, a1, offs1, a2.length);
    }

    public static boolean equals(String a1, char[] a2) {
        return equals(a1, 0, a2);
    }
}
