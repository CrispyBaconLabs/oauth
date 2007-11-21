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

package net.oauth.example.consumer.webapp;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.oauth.OAuth;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import net.oauth.OAuthServiceProvider;
import net.oauth.client.OAuthHttpClient;
import net.oauth.server.OAuthServlet;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;

/**
 * Utility methods for consumers that store tokens and secrets in cookies. Each
 * consumer has a name, and its credentials are stored in cookies named
 * [name].requestToken, [name].accessToken and [name].tokenSecret.
 * 
 * @author John Kristian
 */
public class CookieConsumer {

    public static final Collection<OAuthConsumer> ALL_CONSUMERS = new HashSet<OAuthConsumer>();

    public static final String SIGNATURE_METHOD = "HMAC-SHA1";

    public static HttpClientPool httpClientPool = new HttpClientPool() {
        // This trivial 'pool' simply allocates a new client every time.
        // More efficient implementations are possible.
        public HttpClient getHttpClient(URL server) {
            return new HttpClient();
        }
    };

    private static Properties consumerProperties = null;

    public static synchronized OAuthConsumer newConsumer(String name,
            ServletConfig config) throws IOException {
        Properties p = null;
        synchronized (CookieConsumer.class) {
            p = consumerProperties;
            if (p == null) {
                p = new Properties();
                String resourceName = "/"
                        + CookieConsumer.class.getPackage().getName().replace(
                                ".", "/") + "/consumer.properties";
                URL resource = CookieConsumer.class.getClassLoader()
                        .getResource(resourceName);
                if (resource == null) {
                    throw new IOException("resource not found: " + resourceName);
                }
                InputStream stream = resource.openStream();
                try {
                    p.load(stream);
                } finally {
                    stream.close();
                }
            }
            consumerProperties = p;
        }
        OAuthServiceProvider serviceProvider = new OAuthServiceProvider(p
                .getProperty(name + ".serviceProvider.requestTokenURL"), p
                .getProperty(name + ".serviceProvider.userAuthorizationURL"), p
                .getProperty(name + ".serviceProvider.accessTokenURL"));
        String callbackURL = p.getProperty(name + ".callbackURL");
        if (callbackURL == null) {
            URL resource = config.getServletContext()
                    .getResource(Callback.PATH);
            if (resource != null) {
                callbackURL = resource.toExternalForm();
            } else {
                callbackURL = Callback.PATH;
            }
        }
        OAuthConsumer consumer = new OAuthConsumer(callbackURL //
                , p.getProperty(name + ".consumerKey") //
                , p.getProperty(name + ".consumerSecret"), serviceProvider);
        consumer.setProperty("name", name);
        for (Map.Entry prop : p.entrySet()) {
            String propName = (String) prop.getKey();
            if (propName.startsWith(name + ".consumer.")) {
                String c = propName.substring(name.length() + 10);
                consumer.setProperty(c, prop.getValue());
            }
        }
        return consumer;
    }

    /**
     * Get the access token and token secret for the given consumer. Get them
     * from cookies if possible; otherwise obtain them from the service
     * provider. In the latter case, this method throws RedirectException.
     */
    public static CookieMap getCredentials(HttpServletRequest request,
            HttpServletResponse response, OAuthConsumer consumer)
            throws Exception {
        String consumerName = (String) consumer.getProperty("name");
        CookieMap cookies = new CookieMap(request, response);
        String accessToken = cookies.get(consumerName + ".accessToken");
        if (accessToken == null) {
            CookieConsumer.getAccessToken(request, consumer, cookies);
        }
        return cookies;
    }

    public static void getAccessToken(HttpServletRequest request,
            OAuthConsumer consumer, CookieMap cookies) throws Exception {
        HttpMethod method = invoke(consumer,
                consumer.serviceProvider.requestTokenURL, null,
                (List<OAuth.Parameter>) null);
        String responseBody = method.getResponseBodyAsString();
        final Map<String, String> t = OAuth.newMap(OAuth
                .decodeForm(responseBody));
        String requestToken = t.get("oauth_token");
        String tokenSecret = t.get("oauth_token_secret");
        String consumerName = (String) consumer.getProperty("name");
        if (requestToken != null) {
            cookies.put(consumerName + ".requestToken", requestToken);
            cookies.put(consumerName + ".tokenSecret", tokenSecret);
            String authorizationURL = consumer.serviceProvider.userAuthorizationURL;
            if (authorizationURL.startsWith("/")) {
                authorizationURL = (new URL(new URL(request.getRequestURL()
                        .toString()), request.getContextPath()
                        + authorizationURL)).toString();
            }
            URL callbackURL = new URL(new URL(request.getRequestURL()
                    .toString()), request.getContextPath() + Callback.PATH);
            throw new RedirectException(OAuth.addParameters(authorizationURL //
                    , "oauth_token", requestToken //
                    , "oauth_callback", OAuth.addParameters(callbackURL
                            .toString() //
                            , "consumer", consumerName //
                            , "returnTo", getRequestPath(request) //
                            )));
        }
        OAuthProblemException problem = new OAuthProblemException(
                "parameter_absent");
        problem.setParameter("oauth_parameters_absent", "oauth_token");
        problem.getParameters().putAll(
                OAuthHttpClient.getExchange(method, responseBody));
        throw problem;
    }

    /** Reconstruct the requested URL path, complete with query string (if any). */
    private static String getRequestPath(HttpServletRequest request)
            throws MalformedURLException {
        URL url = new URL(OAuthServlet.getRequestURL(request));
        StringBuilder path = new StringBuilder(url.getPath());
        String queryString = url.getQuery();
        if (queryString != null) {
            path.append("?").append(queryString);
        }
        return path.toString();
    }

    public static HttpMethod invoke(OAuthConsumer consumer,
            CookieMap credentials, String url,
            List<? extends Map.Entry> parameters) throws Exception {
        String consumerName = (String) consumer.getProperty("name");
        String accessToken = credentials.get(consumerName + ".accessToken");
        String tokenSecret = null;
        List<Map.Entry> parms = new ArrayList<Map.Entry>(parameters);
        if (accessToken != null) {
            parms.add(new OAuth.Parameter("oauth_token", accessToken));
            tokenSecret = credentials.get(consumerName + ".tokenSecret");
        }
        return invoke(consumer, url, tokenSecret, parms);
    }

    public static HttpMethod invoke(OAuthConsumer consumer, String url,
            String tokenSecret, Collection<? extends Map.Entry> parameters)
            throws Exception {
        Collection<Map.Entry> parms;
        if (parameters == null) {
            parms = new ArrayList<Map.Entry>(6);
        } else {
            parms = new ArrayList<Map.Entry>(parameters);
        }
        Map<String, String> pMap = OAuth.newMap(parms);
        if (pMap.get("oauth_consumer_key") == null) {
            parms.add(new OAuth.Parameter("oauth_consumer_key",
                    consumer.consumerKey));
        }
        String httpMethod = (String) consumer.getProperty("HTTP method");
        if (httpMethod == null) {
            httpMethod = "GET";
        }
        String signatureMethod = pMap.get("oauth_signature_method");
        if (signatureMethod == null) {
            signatureMethod = (String) consumer
                    .getProperty("oauth_signature_method");
            if (signatureMethod == null) {
                signatureMethod = SIGNATURE_METHOD;
            }
            parms.add(new OAuth.Parameter("oauth_signature_method",
                    signatureMethod));
        }
        parms.add(new OAuth.Parameter("oauth_timestamp", (System
                .currentTimeMillis() / 1000)
                + ""));
        parms.add(new OAuth.Parameter("oauth_nonce", System.nanoTime() + ""));
        OAuthMessage message = new OAuthMessage(httpMethod, url, parms);
        message.sign(consumer, tokenSecret);
        String form = OAuth.formEncode(message.getParameters());
        HttpMethod method;
        if ("GET".equals(message.httpMethod)) {
            method = new GetMethod(url);
            method.setQueryString(form);
            // method.addRequestHeader("Authorization", message
            // .getAuthorizationHeader(serviceProvider.userAuthorizationURL));
            method.setFollowRedirects(false);
        } else {
            PostMethod post = new PostMethod(url);
            post.setRequestEntity(new StringRequestEntity(form,
                    OAuth.FORM_ENCODED, null));
            method = post;
        }
        httpClientPool.getHttpClient(new URL(method.getURI().toString()))
                .executeMethod(method);
        OAuthHttpClient.checkResponse(method);
        return method;
    }

    public static void handleException(Exception e, HttpServletRequest request,
            HttpServletResponse response, OAuthConsumer consumer)
            throws IOException, ServletException {
        if (e instanceof RedirectException) {
            RedirectException redirect = (RedirectException) e;
            String targetURL = redirect.getTargetURL();
            if (targetURL != null) {
                response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
                response.setHeader("Location", targetURL);
            }
        } else if (e instanceof OAuthProblemException) {
            OAuthProblemException p = (OAuthProblemException) e;
            String problem = p.getProblem();
            if (consumer != null && RECOVERABLE_PROBLEMS.contains(problem)) {
                try {
                    CookieConsumer.getAccessToken(request, consumer,
                            new CookieMap(request, response));
                } catch (Exception e2) {
                    handleException(e2, request, response, null);
                }
            } else {
                try {
                    StringWriter s = new StringWriter();
                    PrintWriter pw = new PrintWriter(s);
                    e.printStackTrace(pw);
                    pw.flush();
                    p.setParameter("stack trace", s.toString());
                } catch (Exception rats) {
                }
                response.setStatus(p.getHttpStatusCode());
                response.resetBuffer();
                request.setAttribute("OAuthProblemException", p);
                request.getRequestDispatcher //
                        ("/OAuthProblemException.jsp").forward(request,
                                response);
            }
        } else if (e instanceof IOException) {
            throw (IOException) e;
        } else if (e instanceof ServletException) {
            throw (ServletException) e;
        } else if (e instanceof RuntimeException) {
            throw (RuntimeException) e;
        } else {
            throw new ServletException(e);
        }
    }

    /**
     * The names of problems from which a consumer can recover by getting a
     * fresh token.
     */
    private static final Collection<String> RECOVERABLE_PROBLEMS = new HashSet<String>();
    static {
        RECOVERABLE_PROBLEMS.add("token_revoked");
        RECOVERABLE_PROBLEMS.add("token_expired");
        RECOVERABLE_PROBLEMS.add("permission_unknown");
        // In the case of permission_unknown, getting a fresh token
        // will cause the Service Provider to ask the User to decide.
    }

    /** Return the HTML representation of the given plain text. */
    public static String htmlEncode(Object o) {
        if (o == null) {
            return null;
        }
        String s = o.toString();
        int len = s.length();
        // start with a big enough buffer, avoid reallocations
        StringBuilder sb = new StringBuilder(2 * len);
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            switch (c) {
            case '<':
                sb.append("&lt;");
                break;
            case '>':
                sb.append("&gt;");
                break;
            case '&':
                sb.append("&amp;");
                break;
            case '"':
                sb.append("&quot;");
                break;
            default:
                sb.append(c);
                break;
            }
        }
        return sb.toString();
    }

}
