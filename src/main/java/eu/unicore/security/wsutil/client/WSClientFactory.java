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

import org.apache.commons.io.IOUtils;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.configuration.security.ProxyAuthorizationPolicy;
import org.apache.cxf.databinding.AbstractDataBinding;
import org.apache.cxf.endpoint.Client;
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

import eu.unicore.security.wsutil.XmlBinding;
import eu.unicore.util.Log;
import eu.unicore.util.httpclient.HttpClientProperties;
import eu.unicore.util.httpclient.HttpUtils;
import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * Helper to create web service clients using CXF. This class will configure 
 * the client using the configuration provided as {@link IClientConfiguration},
 * setting SSL, SSL authN, HTTP authN, extra HTTP settings etc. as configured.
 * 
 * @author schuller
 * @see HttpUtils
 */
public class WSClientFactory {

	protected static final Logger logger = Log.getLogger(Log.CLIENT, WSClientFactory.class);
	
	protected IClientConfiguration securityProperties;
	protected HttpClientProperties settings;
	
	protected List<Interceptor<? extends Message>> inHandlers;
	protected List<Interceptor<? extends Message>> outHandlers;
	protected List<Interceptor<? extends Message>> faultHandlers;

	/**
	 *
	 * @param securityCfg security configuration (SSL and HTTP authN)
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
	}

	protected void initHandlers()
	{
		faultHandlers = new ArrayList<Interceptor<? extends Message>>();
		inHandlers = new ArrayList<Interceptor<? extends Message>>();
		outHandlers = new ArrayList<Interceptor<? extends Message>>();
		
		if(securityProperties.isMessageLogging()){
			inHandlers.add(new LogInMessageHandler());	
			outHandlers.add(new LogOutMessageHandler());
		}
		inHandlers.add(new CheckUnderstoodHeadersHandler());
		outHandlers.add(new CheckUnderstoodHeadersHandler());
		inHandlers.add(new ConditionalGetInHandler());
		outHandlers.add(new ConditionalGetOutHandler());
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
		setupProxy(proxy, url);
		setupProxyInterface(iFace, getXfireClient(proxy));
		return proxy;
	}
	
	//TODO can this be removed?
	protected <T> void setupProxyInterface(Class<T> iFace, Client xfireClient)
	{
	}

	/**
	 * creates a dynamic client from the wsdl of the service<br/>
	 * TODO if URL is https we are NOT using the current security settings,
	 * but the JDK settings
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
	 * @param proxy
	 */
	protected void doAddHandlers(Object proxy){
		Client client = getXfireClient(proxy);
		
		List<Interceptor<? extends Message>> l=getOutHandlers();
		if(l!=null){
			for(Interceptor<? extends Message> h:l){ 
				client.getOutInterceptors().add(h);
			}
		}
		List<Interceptor<? extends Message>> l2=getInHandlers();
		if(l2!=null){
			for(Interceptor<? extends Message> h:l2){ 
				client.getInInterceptors().add(h);
			}
		}
		List<Interceptor<? extends Message>> l3=getFaultHandlers();
		if(l3!=null){
			for(Interceptor<? extends Message> h:l3){ 
				client.getOutFaultInterceptors().add(h);
			}
		}
	}

	/**
	 * returns a list of out handlers to add to the proxy client
	 * @return
	 */
	protected List<Interceptor<? extends Message>>getOutHandlers(){
		return outHandlers;
	}

	/**
	 * returns a list of in handlers to add to the proxy client
	 * @return
	 */
	protected List<Interceptor<? extends Message>>getInHandlers(){
		return inHandlers;
	}

	/**
	 * returns a list of fault handlers to add to the proxy client
	 * @return
	 */
	protected List<Interceptor<? extends Message>>getFaultHandlers(){
		return faultHandlers;
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
		
		if(securityProperties.doHttpAuthn()){
			AuthorizationPolicy httpAuth=new AuthorizationPolicy();
			httpAuth.setUserName(securityProperties.getHttpUser());
			httpAuth.setPassword(securityProperties.getHttpPassword());
			http.setAuthorization(httpAuth);
		}
		
		if (!isLocal(uri))
		{
			TLSClientParameters params = new TLSClientParameters();
			params.setSSLSocketFactory(new MySSLSocketFactory(securityProperties));
			params.setDisableCNCheck(true);
			http.setTlsClientParameters(params);
			configureHttpProxy(http, uri);
		}
		
		//timeouts
		http.getClient().setConnectionTimeout(settings.getIntValue(HttpClientProperties.CONNECT_TIMEOUT));
		http.getClient().setReceiveTimeout(settings.getIntValue(HttpClientProperties.SO_TIMEOUT));
		
		//TODO gzip - how? Probably there is some interceptor for it?!
		//boolean gzipEnabled = Boolean.parseBoolean(properties.getProperty(GZIP_ENABLE, "true"));
		
		if(settings.getBooleanValue(HttpClientProperties.CONNECTION_CLOSE)){
			http.getClient().setConnection(ConnectionType.CLOSE);
		}
		
		boolean allowChunking=settings.getBooleanValue(HttpClientProperties.ALLOW_CHUNKING);
		http.getClient().setAllowChunking(allowChunking);
		
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
	 * Configure the XFire proxy: sets up security (SSL/HTTP authn),
	 * Gzip compression, HTTP proxy. 
	 *  
	 * @param proxy Proxy to be configured.
	 * @param cnf Security configuration.
	 */
	protected void setupProxy(Object proxy, String uri)
	{
		setupWSClientProxy(getXfireClient(proxy), uri);
	}
	
	public static Client getXfireClient(Object proxy)
	{
		return ClientProxy.getClient(proxy);
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
	
}
