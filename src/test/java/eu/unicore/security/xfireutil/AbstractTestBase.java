package eu.unicore.security.xfireutil;


import java.util.List;
import java.util.Properties;

import javax.xml.namespace.QName;

import junit.framework.TestCase;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.configuration.security.ProxyAuthorizationPolicy;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.frontend.ClientProxyFactoryBean;
import org.apache.cxf.interceptor.Interceptor;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.jaxws.JaxWsServerFactoryBean;
import org.apache.cxf.message.Message;
import org.apache.cxf.service.factory.ReflectionServiceFactoryBean;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.http.auth.DefaultBasicAuthSupplier;
import org.apache.cxf.transport.http.auth.HttpAuthSupplier;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import org.apache.cxf.xmlbeans.XmlBeansDataBinding;

import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.unicore.security.util.client.HttpUtils;
import eu.unicore.security.util.client.IClientConfiguration;
import eu.unicore.security.xfireutil.client.LogInMessageHandler;
import eu.unicore.security.xfireutil.client.MySSLSocketFactory;

/**
 * @author schuller
 * @author golbi
 */
public abstract class AbstractTestBase extends TestCase
{
	public static final String BASE_URL = "https://localhost:64345";

	protected JettyServer jetty; 

	protected String serviceName="SimpleSecurityService";
	protected QName serviceQName=new QName("foo", serviceName);
	
	protected void setUp() throws Exception
	{

		CXFNonSpringServlet servlet=new CXFNonSpringServlet();
		jetty = new JettyServer(servlet);
		jetty.start();

		JaxWsServerFactoryBean factory=new JaxWsServerFactoryBean();
		factory.setServiceClass(SimpleSecurityServiceImpl.class);
		factory.setBus(servlet.getBus());
		factory.setEndpointName(serviceQName);
		factory.setAddress("/"+serviceName);
		
		List<Interceptor<? extends Message>> s = factory.getInInterceptors();
		AuthInHandler authHandler = new AuthInHandler(true, true, true, null);
		authHandler.addUserAttributeHandler(new SimpleSecurityServiceImpl.SimpleUserAttributeHandler());
		DSigParseInHandler parseHandler = new DSigParseInHandler(null);
		DSigSecurityInHandler dsigHandler = new DSigSecurityInHandler(null);
		AdditionalInHandler addHandler = new AdditionalInHandler();
		ETDInHandler etdHandler=new ETDInHandler(null, new KeystoreCertChainValidator(
				MockSecurityConfig.KS,
				MockSecurityConfig.KS_PASSWD.toCharArray(),
				"JKS", -1));
		
		s.add(authHandler);
//		s.add(parseHandler);
//		s.add(dsigHandler);
		s.add(addHandler);
		s.add(etdHandler);

		s.add(new LogInMessageHandler());
		factory.create();
		
	}

	@Override
	protected void tearDown() throws Exception
	{
		jetty.stop();
	}

	/**
	 * make proxy for the given service
	 * 
	 * @param s
	 * @return proxy
	 * @throws Exception
	 */
	protected SimpleSecurityService makeProxy(IClientConfiguration sec) throws Exception
	{
		JaxWsProxyFactoryBean proxyFactory = new JaxWsProxyFactoryBean();
		proxyFactory.setDataBinding(new XmlBeansDataBinding());
		proxyFactory.setServiceClass(SimpleSecurityService.class);
		
		String addr="https://localhost:" + JettyServer.PORT + "/services/" 
				+ serviceName;
		proxyFactory.setAddress(addr);
		
		SimpleSecurityService serviceProxy = (SimpleSecurityService) proxyFactory.create(); 
		Client client = ClientProxy.getClient(serviceProxy);
		configure(client, sec);
		return serviceProxy;
	}
	
	protected SimpleSecurityService makePlainProxy(IClientConfiguration sec) throws Exception
	{
		JaxWsProxyFactoryBean proxyFactory = new JaxWsProxyFactoryBean();
		proxyFactory.setDataBinding(new XmlBeansDataBinding());
		proxyFactory.setServiceClass(SimpleSecurityService.class);
		
		String addr="http://localhost:" + (JettyServer.PORT+1) + "/services/" 
				+ serviceName;
		proxyFactory.setAddress(addr);
		
		SimpleSecurityService serviceProxy = (SimpleSecurityService) proxyFactory.create(); 
		Client client = ClientProxy.getClient(serviceProxy);
		configure(client, sec);
		return serviceProxy;
	}


	protected SimpleSecurityService makeSecuredProxy(IClientConfiguration sec) throws Exception
	{
		JaxWsProxyFactoryBean proxyFactory = new JaxWsProxyFactoryBean();
		proxyFactory.setServiceClass(SimpleSecurityService.class);
		String addr="https://localhost:" + JettyServer.PORT + "/services/" 
				+ serviceName;

		proxyFactory.setAddress(addr);
		SimpleSecurityService serviceProxy = (SimpleSecurityService) proxyFactory.create(); 
		Client client = ClientProxy.getClient(serviceProxy);
		configure(client, sec);
		
		return serviceProxy;
	}

	//TODO remove when clientFactories are available
	private void configure(Client client, IClientConfiguration sec){
		HTTPConduit http = (HTTPConduit) client.getConduit();
		TLSClientParameters params = new TLSClientParameters();
		params.setSSLSocketFactory(new MySSLSocketFactory(sec));
		params.setDisableCNCheck(true);
		http.setTlsClientParameters(params);

		if(sec.doHttpAuthn()){
			AuthorizationPolicy httpAuth=new AuthorizationPolicy();
			httpAuth.setUserName(sec.getHttpUser());
			httpAuth.setPassword(sec.getHttpPassword());
			http.setAuthorization(httpAuth);
		}
		Properties p=sec.getExtraSettings();
		if(p.getProperty(HttpUtils.HTTP_PROXY_HOST)!=null){
			http.getClient().setProxyServer(p.getProperty(HttpUtils.HTTP_PROXY_HOST));
		}
		if(p.getProperty(HttpUtils.HTTP_PROXY_PORT)!=null){
			http.getClient().setProxyServerPort(Integer.parseInt(p.getProperty(HttpUtils.HTTP_PROXY_PORT)));
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
}
