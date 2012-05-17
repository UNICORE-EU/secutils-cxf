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


package eu.unicore.security.xfireutil.client;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.configuration.security.ProxyAuthorizationPolicy;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.interceptor.Interceptor;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.jaxws.endpoint.dynamic.JaxWsDynamicClientFactory;
import org.apache.cxf.message.Message;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.ConnectionType;
import org.apache.cxf.transports.http.configuration.ProxyServerType;
import org.apache.log4j.Logger;

import eu.unicore.security.util.Log;
import eu.unicore.security.util.client.HttpUtils;
import eu.unicore.security.util.client.IClientConfiguration;

/**
 * Helper to create web service clients using XFire. This class will configure 
 * the client using the configuration provided as {@link IClientConfiguration},
 * setting SSL, SSL authN, HTTP authN, extra HTTP settings etc. as configured.
 * 
 * @author schuller
 * @see HttpUtils
 */
public class XFireClientFactory {

	protected static final Logger logger = Log.getLogger(Log.CLIENT, XFireClientFactory.class);

	//FIXME - this configuration should go to one place
	/** Whether to enable gzip compression*/
	public static final String GZIP_ENABLE = "http.gzipEnable";
	/** Whether to log incoming responses */
	public static final String LOG_INCOMING = "log.incoming";
	/** Whether to log outgoing requests */
	public static final String LOG_OUTGOING = "log.outgoing";
	
	protected IClientConfiguration securityProperties;
	protected Properties settings;
	
	protected List<Interceptor<? extends Message>> inHandlers;
	protected List<Interceptor<? extends Message>> outHandlers;
	protected List<Interceptor<? extends Message>> faultHandlers;

	/**
	 *
	 * @param securityCfg security configuration (SSL and HTTP authN)
	 */
	public XFireClientFactory(IClientConfiguration securityCfg)
	{
		if (securityCfg == null)
			throw new IllegalArgumentException("IAuthenticationConfiguration can not be null");
		if (securityCfg.getExtraSettings() == null)
			throw new IllegalArgumentException("Properties can not be null");
		this.securityProperties = securityCfg.clone();
		this.settings = securityCfg.getExtraSettings();
		initHandlers();
	}

	protected void initHandlers()
	{
		faultHandlers = new ArrayList<Interceptor<? extends Message>>();
		inHandlers = new ArrayList<Interceptor<? extends Message>>();
		if("true".equals(settings.getProperty(LOG_INCOMING))){
			inHandlers.add(new LogInMessageHandler());
		}
		inHandlers.add(new CheckUnderstoodHeadersHandler());
		outHandlers = new ArrayList<Interceptor<? extends Message>>();
		if("true".equals(settings.getProperty(LOG_OUTGOING))){
			outHandlers.add(new LogOutMessageHandler());
		}
		outHandlers.add(new CheckUnderstoodHeadersHandler());
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
		T proxy=factory.create(iFace);
		doAddHandlers(proxy);
		setupProxy(proxy, securityProperties, settings, url);
		setupProxyInterface(iFace, getXfireClient(proxy), 
				securityProperties, settings);
		return proxy;
	}
	
	protected <T> void setupProxyInterface(Class<T> iFace, Client xfireClient, 
			IClientConfiguration cnf, Properties properties)
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
		setupProxy(client,securityProperties,settings,url);
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
	protected void setupProxy(Client client, IClientConfiguration cnf, 
		Properties properties, String uri)
	{

		HTTPConduit http = (HTTPConduit) client.getConduit();
		
		if(cnf.doHttpAuthn()){
			AuthorizationPolicy httpAuth=new AuthorizationPolicy();
			httpAuth.setUserName(cnf.getHttpUser());
			httpAuth.setPassword(cnf.getHttpPassword());
			http.setAuthorization(httpAuth);
		}
		
		if (!isLocal(uri))
		{
			
			TLSClientParameters params = new TLSClientParameters();
			params.setSSLSocketFactory(new MySSLSocketFactory(cnf));
			params.setDisableCNCheck(true);
			http.setTlsClientParameters(params);
			
			Properties p=cnf.getExtraSettings();
			
			configureHttpProxy(http, uri, properties);
			
			if(p.getProperty(HttpUtils.HTTP_PROXY_HOST)!=null){
				http.getClient().setProxyServer(p.getProperty(HttpUtils.HTTP_PROXY_HOST));
			}
			if(p.getProperty(HttpUtils.HTTP_PROXY_PORT)!=null){
				http.getClient().setProxyServerPort(Integer.parseInt(p.getProperty(HttpUtils.HTTP_PROXY_PORT)));
			}
			if(p.getProperty("http.proxyType")!=null){
				if("SOCKS".equalsIgnoreCase(p.getProperty("http.proxyType"))){
					http.getClient().setProxyServerType(ProxyServerType.SOCKS);
				}
			}
			
			if(p.getProperty(HttpUtils.HTTP_PROXY_USER)!=null){
				ProxyAuthorizationPolicy ap=new ProxyAuthorizationPolicy();
				ap.setUserName(p.getProperty(HttpUtils.HTTP_PROXY_USER));
				if(p.getProperty(HttpUtils.HTTP_PROXY_PASS)!=null){
					ap.setPassword(p.getProperty(HttpUtils.HTTP_PROXY_PASS));
				}
				http.setProxyAuthorization(ap);
			}
		}
		
		//timeouts
		String connectTimeout=properties.getProperty(HttpUtils.CONNECT_TIMEOUT, "30000");
		try{
			http.getClient().setConnectionTimeout(Integer.parseInt(connectTimeout));
		}catch(NumberFormatException fe){
			logger.warn("Illegal connection timeout specified: "+connectTimeout);
		}
		
		String socketTimeout=properties.getProperty(HttpUtils.SO_TIMEOUT, "60000");
		try{
			http.getClient().setReceiveTimeout(Integer.parseInt(socketTimeout));
		}catch(NumberFormatException fe){
			logger.warn("Illegal socket timeout specified: "+socketTimeout);
		}
		
		//TODO gzip - how? Probably there is some interceptor for it?!
		//boolean gzipEnabled = Boolean.parseBoolean(properties.getProperty(GZIP_ENABLE, "true"));
		
		String noKeepAlive=properties.getProperty("http.disable-keep-alive","true");
		if(Boolean.getBoolean(noKeepAlive)){
			http.getClient().setConnection(ConnectionType.CLOSE);
		}
		
	}

	private void configureHttpProxy(HTTPConduit http, String uri, Properties properties){
		if (isNonProxyHost(uri, properties)) 
			return;

		// Setup the proxy settings
		String proxyHost = (String) properties.getProperty(HttpUtils.HTTP_PROXY_HOST);
		if (proxyHost == null)
		{
			proxyHost = System.getProperty(HttpUtils.HTTP_PROXY_HOST);
		}

		if (proxyHost != null && proxyHost.trim().length()>0)
		{ 
			String portS = (String) properties.getProperty(HttpUtils.HTTP_PROXY_PORT);
			if (portS == null)
			{
				portS = System.getProperty(HttpUtils.HTTP_PROXY_PORT);
			}
			int port = 80;
			if (portS != null)
				port = Integer.parseInt(portS);

			http.getClient().setProxyServer(proxyHost);
			http.getClient().setProxyServerPort(port);
			
			String proxyType=properties.getProperty("http.proxyType");
			if(proxyType!=null){
				if("SOCKS".equalsIgnoreCase(proxyType)){
					http.getClient().setProxyServerType(ProxyServerType.SOCKS);
				}
			}
			
			String user=properties.getProperty(HttpUtils.HTTP_PROXY_USER);
			if(user!=null){
				ProxyAuthorizationPolicy ap=new ProxyAuthorizationPolicy();
				ap.setUserName(user);
				String password=properties.getProperty(HttpUtils.HTTP_PROXY_PASS);
				if(password!=null){
					ap.setPassword(password);
				}
				http.setProxyAuthorization(ap);
			}
		}

	}

	private boolean isNonProxyHost(String uri, Properties properties){
		String nonProxyHosts=properties.getProperty(HttpUtils.HTTP_NON_PROXY_HOSTS);
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
	protected void setupProxy(Object proxy, IClientConfiguration cnf, 
		Properties properties, String uri)
	{
		setupProxy(getXfireClient(proxy), cnf, properties, uri);
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
		GetMethod method = new GetMethod(wsdlurl);
		client.executeMethod(method);
		return method.getResponseBodyAsString();
	}
}
