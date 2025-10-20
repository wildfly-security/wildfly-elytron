/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.http.oidc;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
class OidcClientUriBuilder {

    private String host;
    private String scheme;
    private int port = -1;

    private boolean preserveDefaultPort = false;

    private String userInfo;
    private String path;
    private String query;
    private String fragment;
    private String ssp;
    private String authority;

    public static OidcClientUriBuilder fromUri(String uriTemplate) {
        // default fromUri manages template params {}
        return new OidcClientUriBuilder().uri(uriTemplate, true);
    }

    public static OidcClientUriBuilder fromPath(String path) throws IllegalArgumentException {
        return new OidcClientUriBuilder().path(path);
    }


    public OidcClientUriBuilder clone() {
        OidcClientUriBuilder impl = new OidcClientUriBuilder();
        impl.host = host;
        impl.scheme = scheme;
        impl.port = port;
        impl.userInfo = userInfo;
        impl.path = path;
        impl.query = query;
        impl.fragment = fragment;
        impl.ssp = ssp;
        impl.authority = authority;

        return impl;
    }

    private static final Pattern opaqueUri = Pattern.compile("^([^:/?#]+):([^/].*)");
    private static final Pattern hierarchicalUri = Pattern.compile("^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?");
    private static final Pattern hostPortPattern = Pattern.compile("([^/:]+):(\\d+)");

    public static boolean compare(String s1, String s2) {
        if (s1 == s2) return true;
        if (s1 == null || s2 == null) return false;
        return s1.equals(s2);
    }

    public static URI relativize(URI from, URI to) {
        if (!compare(from.getScheme(), to.getScheme())) return to;
        if (!compare(from.getHost(), to.getHost())) return to;
        if (from.getPort() != to.getPort()) return to;
        if (from.getPath() == null && to.getPath() == null) return URI.create("");
        else if (from.getPath() == null) return URI.create(to.getPath());
        else if (to.getPath() == null) return to;


        String fromPath = from.getPath();
        if (fromPath.startsWith("/")) fromPath = fromPath.substring(1);
        String[] fsplit = fromPath.split("/");
        String toPath = to.getPath();
        if (toPath.startsWith("/")) toPath = toPath.substring(1);
        String[] tsplit = toPath.split("/");

        int f = 0;

        for (; f < fsplit.length && f < tsplit.length; f++) {
            if (!fsplit[f].equals(tsplit[f])) break;
        }

        OidcClientUriBuilder builder = OidcClientUriBuilder.fromPath("");
        for (int i = f; i < fsplit.length; i++) builder.path("..");
        for (int i = f; i < tsplit.length; i++) builder.path(tsplit[i]);
        return builder.build();
    }

    /**
     * You may put path parameters anywhere within the uriTemplate except port
     *
     * @param uriTemplate
     * @return
     */
    public static OidcClientUriBuilder fromTemplate(String uriTemplate) {
        OidcClientUriBuilder impl = new OidcClientUriBuilder();
        impl.uriTemplate(uriTemplate);
        return impl;
    }

    /**
     * You may put path parameters anywhere within the uriTemplate except port
     *
     * @param uriTemplate
     * @return
     */
    public OidcClientUriBuilder uriTemplate(String uriTemplate) {
        return uri(uriTemplate, true);
    }

    protected OidcClientUriBuilder parseHierarchicalUri(String uri, Matcher match, boolean template) {
        boolean scheme = match.group(2) != null;
        if (scheme) this.scheme = match.group(2);
        String authority = match.group(4);
        if (authority != null) {
            this.authority = null;
            String host = match.group(4);
            int at = host.indexOf('@');
            if (at > -1) {
                String user = host.substring(0, at);
                host = host.substring(at + 1);
                replaceUserInfo(user, template);
            }
            Matcher hostPortMatch = hostPortPattern.matcher(host);
            if (hostPortMatch.matches()) {
                this.host = hostPortMatch.group(1);
                try {
                    this.port = Integer.parseInt(hostPortMatch.group(2));
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Illegal uri template: " + uri, e);
                }
            } else {
                this.host = host;
            }
        }
        if (match.group(5) != null) {
            String group = match.group(5);
            if (!scheme && !"".equals(group) && !group.startsWith("/") && group.indexOf(':') > -1)
                throw new IllegalArgumentException("Illegal uri template: " + uri);
            if (!"".equals(group)) replacePath(group, template);
        }
        if (match.group(7) != null) replaceQuery(match.group(7), template);
        if (match.group(9) != null) fragment(match.group(9), template);
        return this;
    }

    public OidcClientUriBuilder uri(String uri) throws IllegalArgumentException {
        // default uri manages template params {}
        return uri(uri, true);
    }

    public OidcClientUriBuilder uri(String uri, boolean template) throws IllegalArgumentException {
        if (uri == null) throw new IllegalArgumentException("uri parameter is null");
        Matcher opaque = opaqueUri.matcher(uri);
        if (opaque.matches()) {
            this.authority = null;
            this.host = null;
            this.port = -1;
            this.userInfo = null;
            this.query = null;
            this.scheme = opaque.group(1);
            this.ssp = opaque.group(2);
            return this;
        } else {
            Matcher match = hierarchicalUri.matcher(uri);
            if (match.matches()) {
                ssp = null;
                return parseHierarchicalUri(uri, match, template);
            }
        }
        throw new IllegalArgumentException("Illegal uri template: " + uri);
    }

    public OidcClientUriBuilder uri(URI uri) throws IllegalArgumentException {
        if (uri == null) throw new IllegalArgumentException("URI was null");

        if (uri.getRawFragment() != null) fragment = uri.getRawFragment();

        if (uri.isOpaque()) {
            scheme = uri.getScheme();
            ssp = uri.getRawSchemeSpecificPart();
            return this;
        }

        if (uri.getScheme() == null) {
            if (ssp != null) {
                if (uri.getRawSchemeSpecificPart() != null) {
                    ssp = uri.getRawSchemeSpecificPart();
                    return this;
                }
            }
        } else {
            scheme = uri.getScheme();
        }

        ssp = null;
        if (uri.getRawAuthority() != null) {
            if (uri.getRawUserInfo() == null && uri.getHost() == null && uri.getPort() == -1) {
                authority = uri.getRawAuthority();
                userInfo = null;
                host = null;
                port = -1;
            } else {
                authority = null;
                if (uri.getRawUserInfo() != null) {
                    userInfo = uri.getRawUserInfo();
                }
                if (uri.getHost() != null) {
                    host = uri.getHost();
                }
                if (uri.getPort() != -1) {
                    port = uri.getPort();
                }
            }
        }

        if (uri.getRawPath() != null && uri.getRawPath().length() > 0) {
            path = uri.getRawPath();
        }
        if (uri.getRawQuery() != null && uri.getRawQuery().length() > 0) {
            query = uri.getRawQuery();
        }

        return this;
    }

    protected static String paths(boolean encode, String basePath, String... segments) {
        String path = basePath;
        if (path == null) path = "";
        for (String segment : segments) {
            if ("".equals(segment)) continue;
            if (path.endsWith("/")) {
                if (segment.startsWith("/")) {
                    segment = segment.substring(1);
                    if ("".equals(segment)) continue;
                }
                if (encode) segment = Encode.encodePath(segment);
                path += segment;
            } else {
                if (encode) segment = Encode.encodePath(segment);
                if ("".equals(path)) {
                    path = segment;
                } else if (segment.startsWith("/")) {
                    path += segment;
                } else {
                    path += "/" + segment;
                }
            }

        }
        return path;
    }

    public OidcClientUriBuilder path(String segment) throws IllegalArgumentException {
        if (segment == null) throw new IllegalArgumentException("path was null");
        path = paths(true, path, segment);
        return this;
    }

    public OidcClientUriBuilder replaceQuery(String query, boolean template) throws IllegalArgumentException {
        if (query == null || query.length() == 0) {
            this.query = null;
            return this;
        }
        this.query = template? Encode.encodeQueryString(query) : Encode.encodeQueryStringNotTemplateParameters(query);
        return this;
    }

    public OidcClientUriBuilder fragment(String fragment, boolean template) throws IllegalArgumentException {
        if (fragment == null) {
            this.fragment = null;
            return this;
        }
        this.fragment = template? Encode.encodeFragment(fragment) : Encode.encodeFragmentNotTemplateParameters(fragment);
        return this;
    }

    private String buildString(Map<String, ?> paramMap, boolean fromEncodedMap, boolean isTemplate, boolean encodeSlash) {
        for (Map.Entry<String, ? extends Object> entry : paramMap.entrySet()) {
            if (entry.getKey() == null) throw new IllegalArgumentException("map key is null");
            if (entry.getValue() == null) throw new IllegalArgumentException("map value is null");
        }
        StringBuffer buffer = new StringBuffer();

        if (scheme != null)
            replaceParameter(paramMap, fromEncodedMap, isTemplate, scheme, buffer, encodeSlash).append(":");
        if (ssp != null) {
            buffer.append(ssp);
        } else if (userInfo != null || host != null || port != -1) {
            buffer.append("//");
            if (userInfo != null)
                replaceUserInfoParameter(paramMap, fromEncodedMap, isTemplate, userInfo, buffer).append("@");
            if (host != null) {
                if ("".equals(host)) throw new RuntimeException("empty host name");
                replaceParameter(paramMap, fromEncodedMap, isTemplate, host, buffer, encodeSlash);
            }
            if (port != -1 && (preserveDefaultPort || !(("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443)))) {
                buffer.append(":").append(Integer.toString(port));
            }
        } else if (authority != null) {
            buffer.append("//");
            replaceParameter(paramMap, fromEncodedMap, isTemplate, authority, buffer, encodeSlash);
        }
        if (path != null) {
            StringBuffer tmp = new StringBuffer();
            replaceParameter(paramMap, fromEncodedMap, isTemplate, path, tmp, encodeSlash);
            String tmpPath = tmp.toString();
            if (userInfo != null || host != null) {
                if (!tmpPath.startsWith("/")) buffer.append("/");
            }
            buffer.append(tmpPath);
        }
        if (query != null) {
            buffer.append("?");
            replaceQueryStringParameter(paramMap, fromEncodedMap, isTemplate, query, buffer);
        }
        if (fragment != null) {
            buffer.append("#");
            replaceParameter(paramMap, fromEncodedMap, isTemplate, fragment, buffer, encodeSlash);
        }
        return buffer.toString();
    }

    public static Matcher createUriParamMatcher(String string) {
        return PathHelper.URI_PARAM_PATTERN.matcher(PathHelper.replaceEnclosedCurlyBraces(string));
    }

    protected StringBuffer replaceParameter(Map<String, ?> paramMap, boolean fromEncodedMap, boolean isTemplate, String string, StringBuffer buffer, boolean encodeSlash) {
        Matcher matcher = createUriParamMatcher(string);
        while (matcher.find()) {
            String param = matcher.group(1);
            Object valObj = paramMap.get(param);
            if (valObj == null && !isTemplate) {
                throw new IllegalArgumentException("NULL value for template parameter: " + param);
            } else if (valObj == null && isTemplate) {
                matcher.appendReplacement(buffer, matcher.group());
                continue;
            }
            String value = valObj.toString();
            if (value != null) {
                if (!fromEncodedMap) {
                    if (encodeSlash) value = Encode.encodePathSegmentAsIs(value);
                    else value = Encode.encodePathAsIs(value);
                } else {
                    if (encodeSlash) value = Encode.encodePathSegmentSaveEncodings(value);
                    else value = Encode.encodePathSaveEncodings(value);
                }
                matcher.appendReplacement(buffer, Matcher.quoteReplacement(value));
            } else {
                throw new IllegalArgumentException("path param " + param + " has not been provided by the parameter map");
            }
        }
        matcher.appendTail(buffer);
        return buffer;
    }

    protected StringBuffer replaceQueryStringParameter(Map<String, ?> paramMap, boolean fromEncodedMap, boolean isTemplate, String string, StringBuffer buffer) {
        Matcher matcher = createUriParamMatcher(string);
        while (matcher.find()) {
            String param = matcher.group(1);
            Object valObj = paramMap.get(param);
            if (valObj == null && !isTemplate) {
                throw new IllegalArgumentException("NULL value for template parameter: " + param);
            } else if (valObj == null && isTemplate) {
                matcher.appendReplacement(buffer, matcher.group());
                continue;
            }
            String value = valObj.toString();
            if (value != null) {
                if (!fromEncodedMap) {
                    value = Encode.encodeQueryParamAsIs(value);
                } else {
                    value = Encode.encodeQueryParamSaveEncodings(value);
                }
                matcher.appendReplacement(buffer, value);
            } else {
                throw new IllegalArgumentException("path param " + param + " has not been provided by the parameter map");
            }
        }
        matcher.appendTail(buffer);
        return buffer;
    }

    protected StringBuffer replaceUserInfoParameter(Map<String, ?> paramMap, boolean fromEncodedMap, boolean isTemplate, String string, StringBuffer buffer) {
        Matcher matcher = createUriParamMatcher(string);
        while (matcher.find()) {
            String param = matcher.group(1);
            Object valObj = paramMap.get(param);
            if (valObj == null && !isTemplate) {
                throw new IllegalArgumentException("NULL value for template parameter: " + param);
            } else if (valObj == null && isTemplate) {
                matcher.appendReplacement(buffer, matcher.group());
                continue;
            }
            String value = valObj.toString();
            if (value != null) {
                if (!fromEncodedMap) {
                    value = Encode.encodeUserInfoAsIs(value);
                } else {
                    value = Encode.encodeUserInfoSaveEncodings(value);
                }
                matcher.appendReplacement(buffer, value);
            } else {
                throw new IllegalArgumentException("path param " + param + " has not been provided by the parameter map");
            }
        }
        matcher.appendTail(buffer);
        return buffer;
    }

    /**
     * Return a unique order list of path params
     *
     * @return
     */
    public List<String> getPathParamNamesInDeclarationOrder() {
        List<String> params = new ArrayList<String>();
        HashSet<String> set = new HashSet<String>();
        if (scheme != null) addToPathParamList(params, set, scheme);
        if (userInfo != null) addToPathParamList(params, set, userInfo);
        if (host != null) addToPathParamList(params, set, host);
        if (path != null) addToPathParamList(params, set, path);
        if (query != null) addToPathParamList(params, set, query);
        if (fragment != null) addToPathParamList(params, set, fragment);

        return params;
    }

    private void addToPathParamList(List<String> params, HashSet<String> set, String string) {
        Matcher matcher = PathHelper.URI_PARAM_PATTERN.matcher(PathHelper.replaceEnclosedCurlyBraces(string));
        while (matcher.find()) {
            String param = matcher.group(1);
            if (set.contains(param)) continue;
            else {
                set.add(param);
                params.add(param);
            }
        }
    }

    public URI build(Object... values) throws IllegalArgumentException {
        if (values == null) throw new IllegalArgumentException("values parameter is null");
        return buildFromValues(true, false, values);
    }

    public String buildAsString(Object... values) throws IllegalArgumentException {
        if (values == null) throw new IllegalArgumentException("values parameter is null");
        return buildFromValuesAsString(true, false, values);
    }

    protected URI buildFromValues(boolean encodeSlash, boolean encoded, Object... values) {
        String buf = buildFromValuesAsString(encodeSlash, encoded, values);
        try {
            return new URI(buf);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create URI: " + buf, e);
        }
    }

    protected String buildFromValuesAsString(boolean encodeSlash, boolean encoded, Object... values) {
        List<String> params = getPathParamNamesInDeclarationOrder();
        if (values.length < params.size())
            throw new IllegalArgumentException("You did not supply enough values to fill path parameters");

        Map<String, Object> pathParams = new HashMap<String, Object>();
        for (int i = 0; i < params.size(); i++) {
            String pathParam = params.get(i);
            Object val = values[i];
            if (val == null) throw new IllegalArgumentException("A value was null");
            pathParams.put(pathParam, val.toString());
        }
        return buildString(pathParams, encoded, false, encodeSlash);
    }

    public OidcClientUriBuilder matrixParam(String name, Object... values) throws IllegalArgumentException {
        if (name == null) throw new IllegalArgumentException("name parameter is null");
        if (values == null) throw new IllegalArgumentException("values parameter is null");
        if (path == null) path = "";
        for (Object val : values) {
            if (val == null) throw new IllegalArgumentException("null value");
            path += ";" + Encode.encodeMatrixParam(name) + "=" + Encode.encodeMatrixParam(val.toString());
        }
        return this;
    }

    private static final Pattern PARAM_REPLACEMENT = Pattern.compile("_resteasy_uri_parameter");


    public OidcClientUriBuilder queryParam(String name, Object... values) throws IllegalArgumentException {
        if (name == null) throw new IllegalArgumentException("name parameter is null");
        if (values == null) throw new IllegalArgumentException("values parameter is null");
        for (Object value : values) {
            if (value == null) throw new IllegalArgumentException("A passed in value was null");
            if (query == null) query = "";
            else query += "&";
            query += Encode.encodeQueryParamAsIs(name) + "=" + Encode.encodeQueryParamAsIs(value.toString());
        }
        return this;
    }

    public OidcClientUriBuilder replaceQueryParam(String name, Object... values) throws IllegalArgumentException {
        if (name == null) throw new IllegalArgumentException("name parameter is null");
        if (query == null || query.equals("")) {
            if (values != null) return queryParam(name, values);
            return this;
        }

        String[] params = query.split("&");
        query = null;

        String replacedName = Encode.encodeQueryParam(name);


        for (String param : params) {
            int pos = param.indexOf('=');
            if (pos >= 0) {
                String paramName = param.substring(0, pos);
                if (paramName.equals(replacedName)) continue;
            } else {
                if (param.equals(replacedName)) continue;
            }
            if (query == null) query = "";
            else query += "&";
            query += param;
        }
        // don't set values if values is null
        if (values == null) return this;
        return queryParam(name, values);
    }

    public String getHost() {
        return host;
    }

    public String getScheme() {
        return scheme;
    }

    public int getPort() {
        return port;
    }

    public String getUserInfo() {
        return userInfo;
    }

    public String getPath() {
        return path;
    }

    public String getQuery() {
        return query;
    }

    public String getFragment() {
        return fragment;
    }

    public OidcClientUriBuilder replacePath(String path, boolean template) {
        if (path == null) {
            this.path = null;
            return this;
        }
        this.path = template? Encode.encodePath(path) : Encode.encodePathSaveEncodings(path);
        return this;
    }

    public OidcClientUriBuilder replaceUserInfo(String userInfo, boolean template) {
        if (userInfo == null) {
            this.userInfo = null;
            return this;
        }
        this.userInfo = template? Encode.encodeUserInfo(userInfo) : Encode.encodeUserInfoNotTemplateParameters(userInfo);
        return this;
    }

    public URI build(Object[] values, boolean encodeSlashInPath) throws IllegalArgumentException {
        if (values == null) throw new IllegalArgumentException("values param is null");
        return buildFromValues(encodeSlashInPath, false, values);
    }

    public OidcClientUriBuilder resolveTemplates(Map<String, Object> templateValues) throws IllegalArgumentException {
        if (templateValues == null) throw new IllegalArgumentException("templateValues param null");
        String str = buildString(templateValues, false, true, true);
        return fromTemplate(str);
    }
}
