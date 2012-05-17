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

import java.io.ByteArrayInputStream;
import java.lang.reflect.Proxy;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.log4j.Logger;
import org.codehaus.xfire.DefaultXFire;
import org.codehaus.xfire.XFireFactory;
import org.codehaus.xfire.client.Client;
import org.codehaus.xfire.handler.Handler;
import org.codehaus.xfire.service.Service;
import org.codehaus.xfire.service.ServiceFactory;
import org.codehaus.xfire.transport.Channel;
import org.codehaus.xfire.transport.http.AbstractMessageSender;
import org.codehaus.xfire.transport.http.CommonsHttpMessageSender;
import org.codehaus.xfire.transport.http.HttpChannel;

import eu.unicore.security.util.Log;
import eu.unicore.security.util.client.DefaultClientConfiguration;
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
	

	protected final DefaultXFire xfire;
	protected final ReliableProxyFactory proxyMaker;
	protected IClientConfiguration securityProperties;
	protected Properties settings;
	protected ServiceFactory factory;
	
	protected List<Handler> inHandlers;
	protected List<Handler> outHandlers;
	protected List<Handler> faultHandlers;

	/**
	 * This constructor uses {@link JSR181ServiceFactory}.
	 * @param sec
	 */
	public XFireClientFactory(IClientConfiguration sec) 
	{
		this(new JSR181ServiceFactory(), sec);
	}

	/**
	 * Creates factory with default settings: no security, no HTTP proxy, no retires.
	 * @param serviceFactory {@link ServiceFactory} which shall be used to create service
	 * description.
	 */
	public XFireClientFactory(ServiceFactory serviceFactory)
	{
		this(serviceFactory, new DefaultClientConfiguration());
	}

	/**
	 * Creates a factory with all settings.
	 * @param serviceFactory {@link ServiceFactory} which shall be used to create service
	 * description.
	 * @param xfire
	 * @param securityCfg security configuration (SSL and HTTP authN)
	 * @param properties Additional settings. See constants in this class and in {@link HttpUtils} 
	 */
	public XFireClientFactory(ServiceFactory serviceFactory, IClientConfiguration securityCfg)
	{
		if (serviceFactory == null)
			throw new IllegalArgumentException("Service Factory can not be null");
		if (securityCfg == null)
			throw new IllegalArgumentException("IAuthenticationConfiguration can not be null");
		if (securityCfg.getExtraSettings() == null)
			throw new IllegalArgumentException("Properties can not be null");
		this.factory = serviceFactory;
		this.xfire = (DefaultXFire)XFireFactory.newInstance().getXFire();
		this.proxyMaker = new ReliableProxyFactory();
		this.securityProperties = securityCfg.clone();
		this.settings = securityCfg.getExtraSettings();
		initHandlers();
	}

	protected void initHandlers()
	{
		faultHandlers = new ArrayList<Handler>();
		inHandlers = new ArrayList<Handler>();
		if("true".equals(settings.getProperty(LOG_INCOMING))){
			inHandlers.add(new LogInMessageHandler());
		}
		inHandlers.add(new CheckUnderstoodHeadersHandler());
		outHandlers = new ArrayList<Handler>();
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
	@SuppressWarnings("unchecked")
	public synchronized <T> T createPlainWSProxy(Class<T> iFace, String url) 
			throws MalformedURLException
	{
		Service serviceModel = isLocal(url) ? getLocalService(url) : 
			factory.create(iFace);
		
		Object proxy=proxyMaker.create(serviceModel, url);
		doAddHandlers(proxy);
		setupProxy(proxy, securityProperties, settings, url);
		setupProxyInterface(iFace, getXfireClient(proxy), 
				securityProperties, settings);
		return (T)proxy;
	}
	
	protected <T> void setupProxyInterface(Class<T> iFace, Client xfireClient, 
			IClientConfiguration cnf, Properties properties)
	{
	}

	/**
	 * creates a dynamic client from the wsdl of the service
	 *
	 * @param serviceURL the URL, the service can be found
	 * @param sec Security Parameters
	 * @return a Client that supports SSL Connections
	 * @throws Exception
	 */
	public Client createDynamicClient(String url) throws Exception 
	{
		String wsdl = getServiceWSDL(url, securityProperties);		
		Client client = new Client(new ByteArrayInputStream(wsdl.getBytes()), null);
		client.setUrl(url);
		logger.debug("Client created:\n" + "Service Name: "
				+ client.getService().getSimpleName() + "\n" + "Service URL: "
				+ client.getUrl() + "\n");

		setupProxy(client,securityProperties,settings,url);
		return client;
	}

	
	/**
	 * add any handlers directly to the proxy object
	 * @param proxy
	 */
	protected void doAddHandlers(Object proxy){
		Client client = getXfireClient(proxy);
		//use our fixed message sender
		client.setProperty(AbstractMessageSender.MESSAGE_SENDER_CLASS_NAME, HttpMessageSender.class.getName());
		
		List<Handler> l=getOutHandlers();
		if(l!=null){
			for(Handler h:l){ 
				client.addOutHandler(h);
			}
		}
		List<Handler> l2=getInHandlers();
		if(l2!=null){
			for(Handler h:l2){ 
				client.addInHandler(h);
			}
		}
		List<Handler> l3=getFaultHandlers();
		if(l3!=null){
			for(Handler h:l3){ 
				client.addFaultHandler(h);
			}
		}
	}

	/**
	 * returns a list of out handlers to add to the proxy client
	 * @return
	 */
	protected List<Handler>getOutHandlers(){
		return outHandlers;
	}

	/**
	 * returns a list of in handlers to add to the proxy client
	 * @return
	 */
	protected List<Handler>getInHandlers(){
		return inHandlers;
	}

	/**
	 * returns a list of fault handlers to add to the proxy client
	 * @return
	 */
	protected List<Handler>getFaultHandlers(){
		return faultHandlers;
	}

	protected Service getLocalService(String url)
	{
		try{
			//url will be of the form xfire.local://ServiceName/....
			//so we take the "host" part of an URI
			String serviceName=new URI(url).getHost();
			return xfire.getServiceRegistry().getService(serviceName);
		}catch(Exception mue){
			return null;
		}
	}

	protected boolean isLocal(String url)
	{
		if (url == null)
			return false;
		return url.startsWith("xfire.local://");
	}
	
	/**
	 * Configure the XFire proxy: sets up security (SSL/HTTP authn),
	 * Gzip compression, HTTP proxy, HTTP timeouts
	 *  
	 * @param proxy Proxy to be configured.
	 * @param cnf Security configuration.
	 */
	protected void setupProxy(Client xfireClient, IClientConfiguration cnf, 
		Properties properties, String uri)
	{
		Channel channel = xfireClient.getOutChannel();

		if (cnf.doHttpAuthn())
		{
			xfireClient.setProperty(Channel.USERNAME, cnf.getHttpUser());
			xfireClient.setProperty(Channel.PASSWORD, cnf.getHttpPassword());
		}
		
		if (!isLocal(uri))
		{
			if (!(channel instanceof HttpChannel))
				throw new IllegalStateException("Can't configure non" +
						" HTTP channel - it is unsupported. " +
						"Current channel is: " + channel.getClass());
			HttpChannel httpChannel = (HttpChannel) channel;
			HttpClient httpClient = HttpUtils.createClient(properties);
			httpChannel.setProperty(CommonsHttpMessageSender.HTTP_CLIENT, httpClient);
			
			HttpUtils.configureSSL(httpClient, cnf);
			
			if (uri != null)
				HttpUtils.configureProxy(httpClient, uri, properties);
			
			boolean gzipEnabled = Boolean.parseBoolean(
					properties.getProperty(GZIP_ENABLE, "true"));
			httpChannel.setProperty(CommonsHttpMessageSender.GZIP_ENABLED, gzipEnabled);
			String noKeepAlive=properties.getProperty("http.disable-keep-alive","true");
			xfireClient.setProperty(CommonsHttpMessageSender.DISABLE_KEEP_ALIVE, noKeepAlive);
		}
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
		try 
		{
			ReliableProxy xp = (ReliableProxy)Proxy.getInvocationHandler(proxy);
			return xp.getClient();
		} catch (IllegalArgumentException iae)
		{
			return Client.getInstance(proxy);
		} catch (ClassCastException cce)
		{
			return Client.getInstance(proxy);
		}
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
