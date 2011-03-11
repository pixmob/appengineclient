package com.pixmob.appengine.client;

import org.apache.http.client.HttpClient;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;

/**
 * Internal {@link HttpClient} implementation accepting all SSL certificates.
 * With API level 7, the class <code>AndroidHttpClient</code> is not available,
 * and the default {@link HttpClient} implementation does not accept untrusted
 * SSL certificates. This class provides a way for silently accepting these SSL
 * certificates.
 * @author Pixmob
 */
class SSLEnabledHttpClient extends DefaultHttpClient {
    private SSLEnabledHttpClient(ClientConnectionManager manager,
            HttpParams params) {
        super(manager, params);
    }
    
    public static SSLEnabledHttpClient newInstance(String userAgent) {
        // the following code comes from AndroidHttpClient (API level 10)
        
        final HttpParams params = new BasicHttpParams();
        
        // Turn off stale checking. Our connections break all the time anyway,
        // and it's not worth it to pay the penalty of checking every time.
        HttpConnectionParams.setStaleCheckingEnabled(params, false);
        
        final int timeout = 60 * 1000;
        HttpConnectionParams.setConnectionTimeout(params, timeout);
        HttpConnectionParams.setSoTimeout(params, timeout);
        HttpConnectionParams.setSocketBufferSize(params, 8192);
        
        // Don't handle redirects -- return them to the caller. Our code
        // often wants to re-POST after a redirect, which we must do ourselves.
        HttpClientParams.setRedirecting(params, false);
        
        // Set the specified user agent and register standard protocols.
        HttpProtocolParams.setUserAgent(params, userAgent);
        
        final SSLSocketFactory sslSocketFactory = SSLSocketFactory
                .getSocketFactory();
        sslSocketFactory
                .setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
        
        final SchemeRegistry schemeRegistry = new SchemeRegistry();
        schemeRegistry.register(new Scheme("http", PlainSocketFactory
                .getSocketFactory(), 80));
        schemeRegistry.register(new Scheme("https", sslSocketFactory, 443));
        
        final ClientConnectionManager manager = new ThreadSafeClientConnManager(
                params, schemeRegistry);
        return new SSLEnabledHttpClient(manager, params);
    }
}
