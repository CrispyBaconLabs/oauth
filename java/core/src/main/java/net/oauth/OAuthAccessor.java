package net.oauth;

/**
 * Properties of one User of an OAuthConsumer.
 * 
 * @author John Kristian
 */
public class OAuthAccessor {

    public final OAuthConsumer consumer;

    public String requestToken;

    public String accessToken;

    public String tokenSecret;

    public OAuthAccessor(OAuthConsumer consumer) {
        this.consumer = consumer;
    }

}
