/*********************************************************************************
 * Copyright (c) 2006 Forschungszentrum Juelich GmbH 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * (1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer at the end. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * 
 * (2) Neither the name of Forschungszentrum Juelich GmbH nor the names of its 
 * contributors may be used to endorse or promote products derived from this 
 * software without specific prior written permission.
 * 
 * DISCLAIMER
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ********************************************************************************/


package eu.unicore.security.wsutil.client;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.configuration.security.ProxyAuthorizationPolicy;
import org.apache.cxf.databinding.AbstractDataBinding;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.feature.Feature;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.interceptor.Interceptor;
import org.apache.cxf.jaxb.JAXBDataBinding;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.jaxws.endpoint.dynamic.JaxWsDynamicClientFactory;
import org.apache.cxf.message.Message;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.ConnectionType;
import org.apache.cxf.transports.http.configuration.ProxyServerType;
import org.apache.logging.log4j.Logger;

import eu.unicore.security.wsutil.XmlBeansNsHackOutHandler;
import eu.unicore.security.wsutil.XmlBinding;
import eu.unicore.security.wsutil.cxf.XmlBeansDataBinding;
import eu.unicore.util.Log;
import eu.unicore.util.httpclient.HttpClientProperties;
import eu.unicore.util.httpclient.IClientConfiguration;
import eu.unicore.util.httpclient.SessionIDProvider;

/**
 * Helper to create web service clients using CXF. This class will configure 
 * the client using the configuration provided as {@link IClientConfiguration},
 * setting SSL, SSL authN, HTTP authN, extra HTTP settings etc. as configured.
 * 
 * @author schuller
 * @author golbi
 */
public class WSClientFactory {

	public static final String UNICORE_SECURITY_SESSION_TARGET_URL = "unicore-security-session-target-url";

	protected static final Logger logger = Log.getLogger(Log.CLIENT, WSClientFactory.class);
	
	protected IClientConfiguration securityProperties;
	protected HttpClientProperties settings;
	
	protected final List<Interceptor<? extends Message>> inHandlers = new ArrayList<>();
	protected final List<Interceptor<? extends Message>> outHandlers = new ArrayList<>();
	protected final List<Interceptor<? extends Message>> faultHandlers = new ArrayList<>();
	
	protected final List<Feature> features = new ArrayList<>();

	/**
	 * @param securityCfg
	 */
	public WSClientFactory(IClientConfiguration securityCfg)
	{
		if (securityCfg == null)
			throw new IllegalArgumentException("IAuthenticationConfiguration can not be null");
		if (securityCfg.getHttpClientProperties() == null)
			throw new IllegalArgumentException("HTTP settings can not be null");
		this.securityProperties = securityCfg.clone();
		this.settings=securityProperties.getHttpClientProperties();
		initHandlers();
		configureHandlers();
	}

	protected void configureHandlers()
	{
		for (Interceptor<?> i: inHandlers)
		{
			if (i instanceof Configurable)
				((Configurable) i).configure((IClientConfiguration) securityProperties);
		}
		for (Interceptor<?> i: outHandlers)
		{
			if (i instanceof Configurable)
				((Configurable) i).configure((IClientConfiguration) securityProperties);
		}
	}
	
	/**
	 * add default in/out/fault handlers<br/>
	 */
	protected void initHandlers()
	{
		inHandlers.add(new CheckUnderstoodHeadersHandler());
		outHandlers.add(new CheckUnderstoodHeadersHandler());
		outHandlers.add(new XmlBeansNsHackOutHandler());		
		outHandlers.add(new OAuthBearerTokenOutInterceptor());	
	}
	
	/**
	 * Add {@link Feature} classes for client calls. 
	 * Invoked only when the proxy is created.<br/>
	 * The default implementation does nothing
	 */
	protected void initFeatures(){
		if(securityProperties.isMessageLogging()){
			features.add(new LoggingFeature());
		}
	}

	/**
	 * 
	 * Create a proxy for the plain web service at the given URL, 
	 * i.e. not using ws-addressing
	 * 
	 * @param iFace
	 * @param url
	 * @return a proxy for the service defined by the interface iFace
	 * @throws MalformedURLException 
	 * @throws Exception
	 */
	public synchronized <T> T createPlainWSProxy(Class<T> iFace, String url) 
			throws MalformedURLException
	{
		JaxWsProxyFactoryBean factory=new JaxWsProxyFactoryBean();
		factory.setAddress(url);
		AbstractDataBinding binding=getBinding(iFace);
		logger.debug("Using databinding {}", binding.getClass().getName());
		factory.setDataBinding(binding);
		T proxy=factory.create(iFace);
		doAddHandlers(proxy);
		doAddFeatures(proxy);
		setupProxy(proxy, url);
		setupProxyInterface(iFace, getWSClient(proxy));
		return proxy;
	}
	
	protected <T> void setupProxyInterface(Class<T> iFace, Client wsClient)
	{
	}

	/**
	 * creates a dynamic client from the wsdl of the service<br/>
	 * Note: if the URL is https, the JDK SSL settings are used, NOT the 
	 * UNICORE security settings,
	 * 
	 * @param url the URL where the service wsdl can be found
	 * 
	 * @return a Client that supports SSL Connections
	 * @throws Exception
	 */
	public Client createDynamicClient(String url) throws Exception 
	{
		JaxWsDynamicClientFactory dcf = JaxWsDynamicClientFactory.newInstance();
		Client client=dcf.createClient(url);
		setupProxy(client,url);
		return client;
	}

	
	/**
	 * add any handlers directly to the proxy object
	 * 
	 * @param proxy
	 */
	protected void doAddHandlers(Object proxy){
		Client client = getWSClient(proxy);
		for(Interceptor<? extends Message> h: outHandlers){ 
				client.getOutInterceptors().add(h);
		}
		client.getOutInterceptors().add(new CleanupHandler(client));

		for(Interceptor<? extends Message> h: inHandlers){ 
				client.getInInterceptors().add(h);
		}
		for(Interceptor<? extends Message> h:faultHandlers){ 
				client.getOutFaultInterceptors().add(h);
		}
		client.getOutFaultInterceptors().add(new CleanupHandler(client));
	}

	/**
	 * setup features on the proxy object
	 * 
	 * @param proxy
	 */
	protected void doAddFeatures(Object proxy){
		initFeatures();
		Client client = getWSClient(proxy);
		for(Feature f: features){ 
			f.initialize(client, null);	
		}
	}
	
	protected boolean isLocal(String url)
	{
		return url != null && url.startsWith("local://");
	}
	
	/**
	 * Configure the client proxy class: sets up security (SSL/HTTP authn),
	 * Gzip compression, HTTP proxy, HTTP timeouts
	 *  
	 * @param client the Proxy to be configured.
	 * @param uri
	 */
	protected void setupWSClientProxy(Client client, String uri)
	{
		HTTPConduit http = (HTTPConduit) client.getConduit();
		setupHTTPParams(http);
		
	}

	/**
	 * helper method to setup client-side HTTP settings (HTTP auth, TLS, timeouts, proxy, etc)
	 * @param http
	 */
	public void setupHTTPParams(HTTPConduit http){
		
		// HTTP auth
		if(securityProperties.doHttpAuthn()){
			AuthorizationPolicy httpAuth=new AuthorizationPolicy();
			httpAuth.setUserName(securityProperties.getHttpUser());
			httpAuth.setPassword(securityProperties.getHttpPassword());
			http.setAuthorization(httpAuth);
		}
		
		// TLS
		TLSClientParameters params = new TLSClientParameters();
		params.setSSLSocketFactory(new MySSLSocketFactory(securityProperties));
		params.setDisableCNCheck(true);
		http.setTlsClientParameters(params);
		
		// timeouts
		http.getClient().setConnectionTimeout(settings.getIntValue(HttpClientProperties.CONNECT_TIMEOUT));
		http.getClient().setReceiveTimeout(settings.getIntValue(HttpClientProperties.SO_TIMEOUT));
		

		//TODO gzip? CXF has a GZIP Feature 
		//boolean gzipEnabled = Boolean.parseBoolean(properties.getProperty(GZIP_ENABLE, "true"));
		
		if(settings.getBooleanValue(HttpClientProperties.CONNECTION_CLOSE)){
			http.getClient().setConnection(ConnectionType.CLOSE);
		}
		
		boolean allowChunking=settings.getBooleanValue(HttpClientProperties.ALLOW_CHUNKING);
		http.getClient().setAllowChunking(allowChunking);
		
		// http proxy
		String uri=http.getAddress();
		configureHttpProxy(http, uri);
		
	}

	private void configureHttpProxy(HTTPConduit http, String uri){
		if (isNonProxyHost(uri)) 
			return;

		// Setup the proxy settings
		String proxyHost = settings.getValue(HttpClientProperties.HTTP_PROXY_HOST);
		if (proxyHost == null)
		{
			proxyHost = System.getProperty("http."+HttpClientProperties.HTTP_PROXY_HOST);
		}

		if (proxyHost != null && proxyHost.trim().length()>0)
		{ 
			String portS = settings.getValue(HttpClientProperties.HTTP_PROXY_PORT);
			if (portS == null)
			{
				portS = System.getProperty("http."+HttpClientProperties.HTTP_PROXY_PORT);
			}
			int port = 80;
			if (portS != null)
				port = Integer.parseInt(portS);

			http.getClient().setProxyServer(proxyHost);
			http.getClient().setProxyServerPort(port);
			
			String proxyType=settings.getValue(HttpClientProperties.HTTP_PROXY_TYPE);
			http.getClient().setProxyServerType(ProxyServerType.fromValue(proxyType));
			
			String user=settings.getValue(HttpClientProperties.HTTP_PROXY_USER);
			if(user!=null){
				ProxyAuthorizationPolicy ap=new ProxyAuthorizationPolicy();
				ap.setUserName(user);
				String password=settings.getValue(HttpClientProperties.HTTP_PROXY_PASS);
				if(password!=null){
					ap.setPassword(password);
				}
				http.setProxyAuthorization(ap);
			}
		}

	}

	private boolean isNonProxyHost(String uri){
		String nonProxyHosts=settings.getValue(HttpClientProperties.HTTP_NON_PROXY_HOSTS);
		if(nonProxyHosts==null)return false;
		try{
			URI u=new URI(uri);
			String host=u.getHost();
			String[] npHosts=nonProxyHosts.split(" ");
			for(String npHost: npHosts){
				if(host.contains(npHost))return true;
			}
		}catch(URISyntaxException e){
			logger.error("Can't resolve URI from "+uri, e);
		}	

		return false;
	}

	/**
	 * Configure the WS proxy: sets up security (SSL/HTTP authn),
	 * Gzip compression, HTTP proxy. 
	 *  
	 * @param proxy Proxy to be configured.
	 * @param uri
	 */
	protected void setupProxy(Object proxy, String uri)
	{
		Client wsClient=getWSClient(proxy);
		setupWSClientProxy(wsClient, uri);
		if(securityProperties.useSecuritySessions()){
			wsClient.getRequestContext().put(UNICORE_SECURITY_SESSION_TARGET_URL, uri);
		}
	}
	
	/**
	 * get the (implementation-specific) client object
	 * @param proxy - the proxy object
	 */
	public static Client getWSClient(Object proxy)
	{
		return ClientProxy.getClient(proxy);
	}

	public static AbstractDataBinding getBinding(Class<?>clazz){
		XmlBinding annot=(XmlBinding)clazz.getAnnotation(XmlBinding.class);
		if(annot==null || "xmlbeans".equalsIgnoreCase(annot.name())){
			return new XmlBeansDataBinding();
		}
		else if("jaxb".equalsIgnoreCase(annot.name())){
			return new JAXBDataBinding();
		}
		
		throw new IllegalArgumentException("Unknown databinding: "+annot.name());
	}
	
	public SessionIDProvider getSessionIDProvider()
	{
		return securityProperties.getSessionIDProvider();
	}
}
