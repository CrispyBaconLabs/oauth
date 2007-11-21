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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import net.oauth.OAuth;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import org.apache.commons.codec.binary.Base64;

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
            throw problem;
        }
    }

    protected String getSignature(OAuthMessage message) throws Exception {
        return getSignature(getBaseString(message));
    }

    protected void initialize(String name, OAuthConsumer consumer)
            throws Exception {
        String secret = consumer.consumerSecret;
        if (name.endsWith(_ACCESSOR)) {
            Object accessorSecret = consumer
                    .getProperty(OAuthConsumer.ACCESSOR_SECRET);
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

    /** Compute the signature for the given base string. */
    protected abstract String getSignature(String baseString) throws Exception;

    /** Decide whether the signature is valid. */
    protected abstract boolean isValid(String signature, String baseString)
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

    protected String getBaseString(OAuthMessage message) throws IOException {
        return OAuth.percentEncode(message.httpMethod.toUpperCase())
                + '&'
                + OAuth.percentEncode(message.URL)
                + '&'
                + OAuth.percentEncode(normalizeParameters(message
                        .getParameters()));
    }

    protected String normalizeParameters(
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

    /** The factory for signature methods. */
    public static OAuthSignatureMethod newMethod(String name,
            OAuthConsumer consumer) throws Exception {
        Class methodClass = NAME_TO_CLASS.get(name);
        if (methodClass == null) {
            OAuthProblemException problem = new OAuthProblemException(
                    "signature_method_rejected");
            String acceptable = OAuth.percentEncode(NAME_TO_CLASS.keySet());
            if (acceptable.length() > 0) {
                problem.setParameter("oauth_acceptable_signature_methods",
                        acceptable.toString());
            }
            throw problem;
        }
        OAuthSignatureMethod method = (OAuthSignatureMethod) methodClass
                .newInstance();
        method.initialize(name, consumer);
        return method;
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
