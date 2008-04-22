/*
 * Copyright 2007 Netflix, Inc.
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

package net.oauth.signature;

import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;

import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A pair of algorithms for computing and verifying an OAuth digital signature.
 *
 * @author John Kristian
 */
public abstract class OAuthSignatureMethod {

    /** Add a signature to the message. */
    public void sign(OAuthMessage message) throws Exception {
        message.addParameter(new OAuth.Parameter("oauth_signature",
                getSignature(message)));
    }

    /** Add a signature and a body signature to the message */
    public void signWithBody(OAuthMessage authMessage, String contentType,
            byte[] postBody) throws Exception {

        // this sets the xoauth_body_signature parameter
        long start = System.currentTimeMillis();
        signBody(authMessage, contentType, postBody);
        long first = System.currentTimeMillis();

        // this signs all parameters, including the xoauth_body_signature
        // parameter (thus preserving backwards compatibility for SPs that
        // don't support the body signature extension)
        sign(authMessage);
        long second = System.currentTimeMillis();
        System.out.println("body signing: " + (first - start) + "ms. " +
                        "message signing: " + (second - first) + "ms.");
    }

    private void signBody(OAuthMessage message, String contentType,
            byte[] postBody) throws Exception {
        message.addParameter(OAuth.XOAUTH_BODY_SIGNATURE,
                getBodySignature(contentType, postBody));
    }

    private String getBodySignature(
            String contentType,
            byte[] postBody) throws Exception {
        return getSignature(getBodyBaseString(contentType, postBody));
    }

    private byte[] getBodyBaseString(String contentType, byte[] postBody)
            throws UnsupportedEncodingException {

        // TODO: once the spec is finished, we might have to fold in more stuff
        // to sign here. For now, we're signing the content type and post body,
        // separated by exclamation marks.
        byte[] contentTypeBytes = (contentType == null)
                ? new byte[0]
                : contentType.toLowerCase().getBytes(OAuth.ENCODING);

        int length = postBody.length + contentTypeBytes.length + 2;

        ByteBuffer buffer = ByteBuffer.allocate(length);
        buffer.put((byte)33);
        buffer.put(contentTypeBytes);
        buffer.put((byte)33);
        buffer.put(postBody);
        return buffer.array();
    }

    /**
     * Check whether the message has a valid signature.
     *
     * @throws OAuthProblemException
     *             the signature is invalid
     */
    public void validate(OAuthMessage message) throws Exception {
        message.requireParameters("oauth_signature");
        String signature = message.getSignature();
        String baseString = getBaseString(message);
        if (!isValid(signature, baseString)) {
            OAuthProblemException problem = new OAuthProblemException(
                    "signature_invalid");
            problem.setParameter("oauth_signature", signature);
            problem.setParameter("oauth_signature_base_string", baseString);
            problem.setParameter("oauth_signature_method", message
                    .getSignatureMethod());
            throw problem;
        }
    }

    public void validateBodySignature(OAuthMessage message,
            String contentType, byte[] signedBody) throws Exception {
        message.requireParameters(OAuth.XOAUTH_BODY_SIGNATURE);
        String signature = message.getBodySignature();
        if (!isValid(signature, getBodyBaseString(contentType, signedBody))) {
            OAuthProblemException problem = new OAuthProblemException(
                    "body_signature_invalid");
            problem.setParameter("xoauth_body_signature", signature);
            problem.setParameter("oauth_signature_method",
                    message.getSignatureMethod());
            throw problem;
        }
    }

    protected void initialize(String name, OAuthAccessor accessor)
            throws Exception {
        String secret = accessor.consumer.consumerSecret;
        if (name.endsWith(_ACCESSOR)) {
            // This code supports the 'Accessor Secret' extensions
            // described in http://oauth.pbwiki.com/AccessorSecret
            final String key = OAuthConsumer.ACCESSOR_SECRET;
            Object accessorSecret = accessor.getProperty(key);
            if (accessorSecret == null) {
                accessorSecret = accessor.consumer.getProperty(key);
            }
            if (accessorSecret != null) {
                secret = accessorSecret.toString();
            }
        }
        if (secret == null) {
            secret = "";
        }
        setConsumerSecret(secret);
    }

    public static final String _ACCESSOR = "-Accessor";

    protected String getSignature(OAuthMessage message) throws Exception {
        return getSignature(getBaseString(message));
    }

    protected String getSignature(String baseString) throws Exception {
        return getSignature(baseString.getBytes(OAuth.ENCODING));
    }

    /** Compute the signature for the given base string. */
    protected abstract String getSignature(byte[] toSign) throws Exception;

    protected boolean isValid(String signature, String baseString)
            throws Exception  {
        return isValid(signature, baseString.getBytes(OAuth.ENCODING));
    }

    /** Decide whether the signature is valid. */
    protected abstract boolean isValid(String signature, byte[] signed)
            throws Exception;

    private String consumerSecret;

    private String tokenSecret;

    protected String getConsumerSecret() {
        return consumerSecret;
    }

    protected void setConsumerSecret(String consumerSecret) {
        this.consumerSecret = consumerSecret;
    }

    public String getTokenSecret() {
        return tokenSecret;
    }

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    public static String getBaseString(OAuthMessage message)
            throws IOException, URISyntaxException {
        List<Map.Entry<String, String>> parameters;
        String url = message.URL;
        int q = url.indexOf('?');
        if (q < 0) {
            parameters = message.getParameters();
        } else {
            // Combine the URL query string with the other parameters:
            parameters = new ArrayList<Map.Entry<String, String>>();
            parameters.addAll(OAuth.decodeForm(message.URL.substring(q + 1)));
            parameters.addAll(message.getParameters());
            url = url.substring(0, q);
        }
        return OAuth.percentEncode(message.method.toUpperCase()) + '&'
                + OAuth.percentEncode(normalizeUrl(url)) + '&'
                + OAuth.percentEncode(normalizeParameters(parameters));
    }

    protected static String normalizeUrl(String url) throws URISyntaxException {
        URI uri = new URI(url);
        String authority = uri.getAuthority().toLowerCase();
        String scheme = uri.getScheme().toLowerCase();

        boolean dropPort = (scheme.equals("http") && uri.getPort() == 80)
                           || (scheme.equals("https") && uri.getPort() == 443);

        if (dropPort) {
            // find the last : in the authority
            int index = authority.lastIndexOf(":");
            if (index >= 0) {
                authority = authority.substring(0, index);
            }
        }

        // we know that there is no query and no fragment here.
        return new URI(scheme, authority, uri.getPath(), null, null).toString();
    }

    protected static String normalizeParameters(
            Collection<? extends Map.Entry> parameters) throws IOException {
        if (parameters == null) {
            return "";
        }
        List<ComparableParameter> p = new ArrayList<ComparableParameter>(
                parameters.size());
        for (Map.Entry parameter : parameters) {
            if (!"oauth_signature".equals(parameter.getKey())) {
                p.add(new ComparableParameter(parameter));
            }
        }
        Collections.sort(p);
        return OAuth.formEncode(getParameters(p));
    }

    public static byte[] decodeBase64(String s) {
        return BASE64.decode(s.getBytes());
    }

    public static String base64Encode(byte[] b) {
        return new String(BASE64.encode(b));
    }

    private static final Base64 BASE64 = new Base64();

    public static OAuthSignatureMethod newSigner(OAuthMessage message,
            OAuthAccessor accessor) throws Exception {
        message.requireParameters(OAuth.OAUTH_SIGNATURE_METHOD);
        OAuthSignatureMethod signer = newMethod(message.getSignatureMethod(),
                accessor);
        signer.setTokenSecret(accessor.tokenSecret);
        return signer;
    }

    /** The factory for signature methods. */
    public static OAuthSignatureMethod newMethod(String name,
            OAuthAccessor accessor) throws Exception {
        Class methodClass = NAME_TO_CLASS.get(name);
        if (methodClass != null) {
            OAuthSignatureMethod method = (OAuthSignatureMethod) methodClass
                    .newInstance();
            method.initialize(name, accessor);
            return method;
        }
        OAuthProblemException problem = new OAuthProblemException(
                "signature_method_rejected");
        String acceptable = OAuth.percentEncode(NAME_TO_CLASS.keySet());
        if (acceptable.length() > 0) {
            problem.setParameter("oauth_acceptable_signature_methods",
                    acceptable.toString());
        }
        throw problem;
    }

    /**
     * Subsequently, newMethod(name) will attempt to instantiate the given
     * class, with no constructor parameters.
     */
    public static void registerMethodClass(String name, Class clazz) {
        NAME_TO_CLASS.put(name, clazz);
    }

    private static final Map<String, Class> NAME_TO_CLASS = new ConcurrentHashMap<String, Class>();
    static {
        registerMethodClass("HMAC-SHA1", HMAC_SHA1.class);
        registerMethodClass("PLAINTEXT", PLAINTEXT.class);
        registerMethodClass("RSA-SHA1", RSA_SHA1.class);
        registerMethodClass("HMAC-SHA1" + _ACCESSOR, HMAC_SHA1.class);
        registerMethodClass("PLAINTEXT" + _ACCESSOR, PLAINTEXT.class);
    }

    /** An efficiently sortable wrapper around a parameter. */
    private static class ComparableParameter implements
            Comparable<ComparableParameter> {

        ComparableParameter(Map.Entry value) {
            this.value = value;
            String n = toString(value.getKey());
            String v = toString(value.getValue());
            this.key = OAuth.percentEncode(n) + ' ' + OAuth.percentEncode(v);
            // ' ' is used because it comes before any character
            // that can appear in a percentEncoded string.
        }

        final Map.Entry value;

        private final String key;

        private static String toString(Object from) {
            return (from == null) ? null : from.toString();
        }

        public int compareTo(ComparableParameter that) {
            return this.key.compareTo(that.key);
        }

        @Override
        public String toString() {
            return key;
        }

    }

    /** Retrieve the original parameters from a sorted collection. */
    private static List<Map.Entry> getParameters(
            Collection<ComparableParameter> parameters) {
        if (parameters == null) {
            return null;
        }
        List<Map.Entry> list = new ArrayList<Map.Entry>(parameters.size());
        for (ComparableParameter parameter : parameters) {
            list.add(parameter.value);
        }
        return list;
    }
}
