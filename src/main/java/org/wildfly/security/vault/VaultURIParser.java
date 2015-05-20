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
package org.wildfly.security.vault;

import static org.wildfly.security._private.ElytronMessages.log;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * This class provides parsing for URIs with scheme "vault".
 *
 * <p> Vault URI is used for referencing vault storage managed under {@code VaultManager} can
 * specify complete information about vault storage including parameters as well as reference
 * of stored secured attributes (such  as passwords).
 *
 * <h3> Vault URI scheme </h3>
 *
 * <blockquote>
 * vaultURI  =  <i>scheme</i> {@code :} {@code //}<i>vault_name</i> [{@code /} <i>vault_storage_file</i>] [?<i>query</i>] [{@code #} <i>attribute_name</i>]
 *
 * <i>scheme</i> =  <b>vault</b>
 *
 * <i>vault_name</i> = {@code //} alpha *alphanum
 *
 * <i>vault_storage_file</i> = file_name_uri
 *
 * <i>query</i> = vault_parameter = value *[{@code ;} <i>vault_parameter</i> = <i>value</i>]
 *
 * <i>vault_parameter</i> = alpha *alphanum
 *
 * <i>value</i> = {@code '}alpha *alphanum{@code '} {@code |} alpha *alphanum
 *
 * <i>attribute_name</i> = alpha *alphanum
 * </blockquote>
 *
 * <p> vault URI has to be absolute with <b>vault_name></b> always defined.
 * <p> parameters to {@code Vault} implementation are supplied through <b>query</b> part of URI. In case they need to decode binary value Base64 encoding method should be used.
 * Parameters are in form of
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class VaultURIParser {

    /**
     * Vault URI scheme name ("vault").
     */
    public static final String VAULT_SCHEME = "vault";

    private String name;
    private String storageFile;
    private final HashMap<String, String> options = new HashMap<>();
    private String attribute;

    /**
     * Constructor to create this class based on {@code String}
     *
     * @param uri URI to parse
     * @throws java.net.URISyntaxException in case of problems parsing given URI
     */
    public VaultURIParser(final String uri) throws URISyntaxException {
        int schemeInd = 0;
        if (uri.startsWith(VAULT_SCHEME + ":")) {
            schemeInd = 6;  // "vault:".length()
        }
        int fragmentInd = uri.indexOf('#');
        URI uriToParse;
        if (fragmentInd == 0) {
            throw log.vaultHasNoName(safeVaultURI(uri));
        } else if (fragmentInd > -1) {
            String fragment = uri.substring(fragmentInd + 1);
            if (fragment.indexOf('#') > -1) {
                throw new URISyntaxException(uri, log.moreThanOneFragmentDefined(), fragmentInd + fragment.indexOf('#'));
            }
            uriToParse = new URI(VAULT_SCHEME, uri.substring(schemeInd, fragmentInd), fragment);
        } else {
            uriToParse = new URI(VAULT_SCHEME, uri.substring(schemeInd), null);
        }
        parse(uriToParse);
    }

    /**
     * Constructor to create this class based on {@code URI}
     *
     * @param uri URI to parse
     */
    public VaultURIParser(final URI uri) {
        parse(uri);
    }

    private void parse(final URI uri) {
        if (! uri.isAbsolute()) {
            throw log.vaultNotAbsoluteURI(safeVaultURI(uri.toString()));
        }
        if (! VAULT_SCHEME.equals(uri.getScheme())) {
            throw log.vaultURIWrongScheme(safeVaultURI(uri.toString()));
        }

        String authority = uri.getAuthority();
        if (authority != null) {
            name = authority;
        } else {
            throw log.vaultHasNoName(safeVaultURI(uri.toString()));
        }

        String path = uri.getPath();
        if (path != null && path.length() > 1) {
            storageFile = path.substring(1);
        } else {
            storageFile = null;
        }

        parseQueryParameter(uri.getQuery(), uri.toString());

        String fragment = uri.getFragment();
        if (fragment != null && fragment.length() >= 0) {
            if (fragment.isEmpty()) {
                throw log.vaultAttributeNameEmpty(VaultURIParser.safeVaultURI(uri.toString()));
            }
            attribute = fragment;
        } else {
            attribute = null;
        }
    }

    /**
     * Parses and creates {@code options} map with all vault URI query parameters separated.
     * key value pairs are separated by {@code ;} semicolon.
     * @param query part of the vault URI
     * @param uri {@code String} for logging and error messages
     */
    private void parseQueryParameter(final String query, final String uri) {

        if (query == null) {
            return;
        }

        int i = 0;
        int state = 0; // possible states KEY = 0 | VALUE = 1
        StringBuilder token = new StringBuilder();
        String key = null;
        String value = null;
        while (i < query.length()) {
            char c = query.charAt(i);
            if (state == 0) {   // KEY state
                if (c == '=') {
                    state = 1;
                    key = token.toString();
                    value = null;
                    token.setLength(0);
                } else {
                    token.append(c);
                }
                i++;
            } else if (state == 1) {  // VALUE state
                if (c == '\'') {
                    if (query.charAt(i - 1) != '=') {
                        throw log.vaultParameterOpeningQuote(VaultURIParser.safeVaultURI(uri));
                    }
                    int inQuotes = i + 1;
                    c = query.charAt(inQuotes);
                    while (inQuotes < query.length() && c != '\'') {
                        token.append(c);
                        inQuotes++;
                        c = query.charAt(inQuotes);
                    }
                    if (c == '\'') {
                        i = inQuotes + 1;
                        if (i < query.length() && query.charAt(i) != ';') {
                            throw log.vaultParameterClosingQuote(VaultURIParser.safeVaultURI(uri));
                        }
                    } else {
                        throw log.vaultParameterUnexpectedEnd(VaultURIParser.safeVaultURI(uri));
                    }
                } else if (c == ';') {
                    value = token.toString();
                    if (key == null) {
                        throw log.vaultParameterNameExpected(VaultURIParser.safeVaultURI(uri));
                    }
                    // put to options and reset key, value and token
                    options.put(key, value);
                    i++;
                    key = null;
                    value = null;
                    token.setLength(0);
                    // set state to KEY
                    state = 0;
                } else {
                    token.append(c);
                    i++;
                }
            }
        }
        if (key != null && token.length() > 0) {
            options.put(key, token.toString());
        } else {
            throw log.vaultParameterUnexpectedEnd(VaultURIParser.safeVaultURI(uri));
        }

    }

    /**
     * Returns parsed vault name.
     *
     * @return vault name
     */
    public String getName() {
        return name;
    }

    /**
     * @return vault URI scheme (always {@code VAULT_SCHEME})
     */
    public String getScheme() {
        return VAULT_SCHEME;
    }


    /**
     * Transforms given parameter to safely displayed {@code String} by stripping potentially sensitive information from the URI.
     *
     * @param uri original URI string
     * @return {@code String} safe to display
     */
    public static String safeVaultURI(String uri) {
        // for now, just easy stripping
        int startOfQuery = uri.indexOf('?');
        if (startOfQuery > -1) {
            return uri.substring(0, startOfQuery) + "...";
        } else {
            return uri;
        }
    }

    /**
     * If storage file was not specified in vault URI returns {@code null}
     * @return storageFile as parsed from vault URI as {@code String}
     */
    public String getStorageFile() {
        return storageFile;
    }

    /**
     * If attribute was not specified in vault URI returns {@code null}
     * @return attribute specified by vault URI
     */
    public String getAttribute() {
        return attribute;
    }

    /**
     * Fetch parameter value from query string.
     *
     * @param param name of wanted parameter
     * @return parameter value as a {@code String} or {@code null} if parameter was not specified in query part of the URI
     */
    public String getParameter(final String param) {
        return options.get(param);
    }

    /**
     * Returns {@code Set<String>} parameters specified in the vault URI.
     * @return set of parameter names
     */
    public Set<String> getParameters() {
        return options.keySet();
    }

    /**
     * Returns new {@code Map<String, Object>} for use in {@code PasswordStorage} to initialize the password storage.
     * @return Map of options parsed from the vault URI
     */
    public Map<String, String> getOptionsMap() {
        return new HashMap<>(options);
    }

}
