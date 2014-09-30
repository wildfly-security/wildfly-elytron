/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.security.permission;

import static org.wildfly.security.manager._private.SecurityMessages.permission;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Iterator;

import org.wildfly.security.manager._private.SecurityMessages;

/**
 * A helper class for defining permissions which use a finite list of actions.  Define custom permissions using
 * an {@code enum} of actions, where the string representation (via {@code toString()}) of each enum is one possible
 * action name.  Typically the {@code enum} should be non-public, and the constant names should be lowercase.  If
 * an action name contains a character which is not a valid Java identifier, then the {@code toString()} method of
 * such constants should be overridden to report the correct string.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PermissionActions {

    static final class TrieNode<E> {
        private static final char[] C_EMPTY = new char[0];
        private static final TrieNode[] T_EMPTY = new TrieNode[0];

        private E result;
        private char[] matches = C_EMPTY;
        @SuppressWarnings("unchecked")
        private TrieNode<E>[] children = T_EMPTY;

        void put(String s, int idx, E value) {
            if (idx == s.length()) {
                result = value;
                return;
            }
            char c = s.charAt(idx);
            final int i = Arrays.binarySearch(matches, c);
            if (i < 0) {
                // copy and add
                final int oldLength = matches.length;
                final char[] newMatches = Arrays.copyOf(matches, oldLength + 1);
                final TrieNode<E>[] newChildren = Arrays.copyOf(children, oldLength + 1);
                // i is the negated insertion index
                final int insertIndex = -i - 1;
                System.arraycopy(newMatches, insertIndex, newMatches, insertIndex + 1, oldLength - insertIndex);
                System.arraycopy(newChildren, insertIndex, newChildren, insertIndex + 1, oldLength - insertIndex);
                newMatches[insertIndex] = c;
                final TrieNode<E> newNode = new TrieNode<>();
                newChildren[insertIndex] = newNode;
                matches = newMatches;
                children = newChildren;
                newNode.put(s, idx + 1, value);
            } else {
                children[i].put(s, idx + 1, value);
            }
        }

        E get(String s, int idx, int end) {
            if (idx == end) {
                return result;
            }
            final char c = s.charAt(idx);
            final int i = Arrays.binarySearch(matches, c);
            if (i < 0) {
                return null;
            }
            return children[i].get(s, idx + 1, end);
        }
    }

    private static final ClassValue<TrieNode<?>> storedTrie = new ClassValue<TrieNode<?>>() {
        protected TrieNode<?> computeValue(final Class<?> type) {
            return computeReal(type.asSubclass(Enum.class));
        }

        private <E extends Enum<E>> TrieNode<E> computeReal(final Class<E> type) {
            final TrieNode<E> root = new TrieNode<>();
            final E[] enumConstants = type.getEnumConstants();
            for (E e : enumConstants) {
                root.put(e.toString(), 0, e);
            }
            return root;
        }
    };

    /**
     * Parse an action string using the given action type.
     *
     * @param actionType the action {@code enum} type class
     * @param actionString the string to parse
     * @param <E> the action {@code enum} type
     * @return the set of actions from the string
     * @throws IllegalArgumentException if the string contained an invalid action
     */
    public static <E extends Enum<E>> EnumSet<E> parseActionString(Class<E> actionType, String actionString) throws IllegalArgumentException {
        if (actionString == null) {
            throw new IllegalArgumentException("actionString is null");
        }
        if (actionType == null) {
            throw new IllegalArgumentException("actionType is null");
        }
        @SuppressWarnings("unchecked")
        final TrieNode<E> rootNode = (TrieNode<E>) storedTrie.get(actionType);
        boolean star = false;
        // begin parse
        char c;
        final EnumSet<E> set = EnumSet.noneOf(actionType);
        final int length = actionString.length();
        int i = 0;
        L0: for (;;) {
            if (i == length) {
                // OK
                break L0;
            }
            c = actionString.charAt(i);
            if (Character.isWhitespace(c)) {
                i ++;
                continue L0;
            }
            if (c == ',') {
                // hmm, empty segment; ignore it
                i ++;
                continue L0;
            }
            if (c == '*') {
                // potential star
                star = true;
                for (;;) {
                    i ++;
                    if (i == length) {
                        // done
                        break L0;
                    }
                    c = actionString.charAt(i);
                    if (c == ',') {
                        // pointless, but go on
                        i ++;
                        continue L0;
                    }
                    if (! Character.isWhitespace(c)) {
                        throw permission.unexpectedActionCharacter(c, i, actionString);
                    }
                }
                // not reachable
            }
            // else it's a potentially valid character
            int start = i;
            for (;;) {
                i++;
                c = i < length ? actionString.charAt(i) : 0;
                if (i == length || Character.isWhitespace(c) || c == ',') {
                    // action string ends here
                    final E action = rootNode.get(actionString, start, i);
                    if (action == null) {
                        throw permission.invalidAction(actionString.substring(start, i), start, actionString);
                    }
                    set.add(action);
                    if (i == length) {
                        // done
                        break L0;
                    }
                    while (Character.isWhitespace(c)) {
                        i++;
                        if (i == length) {
                            // done
                            break L0;
                        }
                        c = actionString.charAt(i);
                    }
                    if (c != ',') {
                        throw permission.unexpectedActionCharacter(c, i, actionString);
                    }
                    i ++;
                    continue L0;
                }
            }
            // not reachable
        }
        return star ? EnumSet.allOf(actionType) : set;
    }

    /**
     * Get the canonical action string representation for the given action set.
     *
     * @param set the action set
     * @param <E> the action type
     * @return the canonical representation
     */
    public static <E extends Enum<E>> String getCanonicalActionString(EnumSet<E> set) {
        if (set == null || set.isEmpty()) return "";
        final StringBuilder b = new StringBuilder();
        getCanonicalActionString(set, b);
        return b.toString();
    }

    /**
     * Get the canonical action string representation for the given action set, appending it to the given string builder.
     *
     * @param set the action set
     * @param b the string builder
     * @param <E> the action type
     */
    public static <E extends Enum<E>> void getCanonicalActionString(EnumSet<E> set, StringBuilder b) {
        if (set == null || set.isEmpty()) return;
        final Iterator<E> iterator = set.iterator();
        if (iterator.hasNext()) {
            E e = iterator.next();
            b.append(e.toString());
            while (iterator.hasNext()) {
                e = iterator.next();
                b.append(',');
                b.append(e.toString());
            }
        }
    }
}
