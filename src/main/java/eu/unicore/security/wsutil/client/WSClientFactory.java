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
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.configuration.security.ProxyAuthorizationPolicy;
import org.apache.cxf.databinding.AbstractDataBinding;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.feature.Feature;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.interceptor.Interceptor;
import org.apache.cxf.jaxb.JAXBDataBinding;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.jaxws.endpoint.dynamic.JaxWsDynamicClientFactory;
import org.apache.cxf.message.Message;
import org.apache.cxf.service.factory.ReflectionServiceFactoryBean;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.ConnectionType;
import org.apache.cxf.transports.http.configuration.ProxyServerType;
import org.apache.cxf.xmlbeans.XmlBeansDataBinding;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import eu.unicore.security.wsutil.SecuritySessionUtils;
import eu.unicore.security.wsutil.XmlBeansNsHackOutHandler;
import eu.unicore.security.wsutil.XmlBinding;
import eu.unicore.util.Log;
import eu.unicore.util.httpclient.HttpClientProperties;
import eu.unicore.util.httpclient.HttpUtils;
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

	protected static final Logger logger = Log.getLogger(Log.CLIENT, WSClientFactory.class);
	
	protected IClientConfiguration securityProperties;
	protected HttpClientProperties settings;
	
	protected final List<Interceptor<? extends Message>> inHandlers = new ArrayList<Interceptor<? extends Message>>();
	protected final List<Interceptor<? extends Message>> outHandlers = new ArrayList<Interceptor<? extends Message>>();
	protected final List<Interceptor<? extends Message>> faultHandlers = new ArrayList<Interceptor<? extends Message>>();
	
	protected final List<Feature> features = new ArrayList<Feature>();

	/**
	 * @param securityCfg
	 */
	public WSClientFactory(IClientConfiguration securityCfg)
	{
		if (securityCfg == null)
			throw new IllegalArgumentException("IAuthenticationConfiguration can not be null");
		if (securityCfg.getHttpClientProperties() == null)
			throw new IllegalArgumentException("HTTP settings can not be null");
		// I know I'm evil but the error messages from this class just clutter up the logs and make
		// the admins nervous
		Logger.getLogger(ReflectionServiceFactoryBean.class).setLevel(Level.FATAL);
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
		if(securityProperties.isMessageLogging()){
			inHandlers.add(new LogInMessageHandler());	
			outHandlers.add(new LogOutMessageHandler());
		}
		
		inHandlers.add(new CheckUnderstoodHeadersHandler());
		outHandlers.add(new CheckUnderstoodHeadersHandler());

		outHandlers.add(new XmlBeansNsHackOutHandler());
		
		if(securityProperties.useSecuritySessions()){
			inHandlers.add(new SessionIDInHandler());
			outHandlers.add(new SessionIDOutHandler());
		}
	}
	
	/**
	 * Add {@link Feature} classes for client calls. 
	 * Invoked only when the proxy is created.<br/>
	 * The default implementation does nothing
	 */
	protected void initFeatures(){
	}

	/**
	 * 
	 * Create a proxy for the plain web service at the given URL, 
	 * i.e. not using ws-addressing
	 * 
	 * @param iFace
	 * @param url
	 * @param sec
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
		logger.debug("Using databinding "+binding.getClass().getName());
		factory.setDataBinding(binding);
		T proxy=factory.create(iFace);
		doAddHandlers(proxy);
		doAddFeatures(proxy);
		setupRetry(proxy);
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
	 * @param serviceURL the URL where the service wsdl can be found
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
		
		for(Interceptor<? extends Message> h: inHandlers){ 
				client.getInInterceptors().add(h);
		}
		
		for(Interceptor<? extends Message> h:faultHandlers){ 
				client.getOutFaultInterceptors().add(h);
		}
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
		if (url == null)
			return false;
		return url.startsWith("local://");
	}
	
	/**
	 * Configure the client proxy class: sets up security (SSL/HTTP authn),
	 * Gzip compression, HTTP proxy, HTTP timeouts
	 *  
	 * @param client the Proxy to be configured.
	 * @param cnf Security configuration.
	 * @param properties
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
	
	/**
	 * Create a new and ready-to-use {@link RetryFeature} instance. This object might be further customized by 
	 * adding additional recoverable exceptions, besides {@link SocketTimeoutException} which is by default set.
	 */
	public RetryFeature getDefaultRetryFeature(){
		RetryFeature r = new RetryFeature(this);
		r.setMaxRetries(securityProperties.getMaxWSRetries());
		r.setDelayBetweenRetries(securityProperties.getRetryDelay());
		r.getRecoverableExceptions().add(SocketTimeoutException.class);
		return r;
	}


	/**
	 * Configure the given proxy object with the retry feature<br/>
	 * The retry feature can later be retrieved with {@link #getRetryFeature(Object)}
	 * 
	 * @param proxy - the WS proxy
	 * @param retry - the {@link RetryFeature}
	 */
	public void setupRetry(Object proxy, RetryFeature retry){
		Client client = getWSClient(proxy);
		retry.initialize(client, null);	
		client.getRequestContext().put(RetryFeature.class.getName(), retry);
	}
	
	/**
	 * setup the default retry feature
	 * @param proxy
	 */
	public void setupRetry(Object proxy){
		setupRetry(proxy, getDefaultRetryFeature());
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
	 * @param cnf Security configuration.
	 */
	protected void setupProxy(Object proxy, String uri)
	{
		Client wsClient=getWSClient(proxy);
		setupWSClientProxy(wsClient, uri);
		if(securityProperties.useSecuritySessions()){
			wsClient.getRequestContext().put(SecuritySessionUtils.SESSION_TARGET_URL, uri);
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

	/**
	 * get the {@link RetryFeature} configured for the given proxy object
	 * @param proxy
	 * @return retry feature or <code>null</code> if not yet set
	 */
	public static RetryFeature getRetryFeature(Object proxy)
	{
		Client c = getWSClient(proxy);
		return (RetryFeature) c.getRequestContext().get(RetryFeature.class.getName());
	}

	/**
	 * For creating a client from WSDL, we need the WSDL of the service. 
	 * 
	 * @param url The URL of the service
	 * @param sec The ISecurityProperties to enable an SSL Connection
	 * @return the Service WSDL as a String
	 * @throws Exception
	 */
	protected String getServiceWSDL(String url, IClientConfiguration sec) throws Exception 
	{
		HttpClient client = HttpUtils.createClient(url, sec);
		String wsdlurl = url + "?wsdl";
		HttpGet method = new HttpGet(wsdlurl);
		HttpResponse response=client.execute(method);
		return IOUtils.toString(response.getEntity().getContent());
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
