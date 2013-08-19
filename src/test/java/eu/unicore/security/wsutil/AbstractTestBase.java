package eu.unicore.security.wsutil;


import java.util.List;

import javax.xml.namespace.QName;

import junit.framework.TestCase;

import org.apache.cxf.interceptor.Interceptor;
import org.apache.cxf.jaxws.JaxWsServerFactoryBean;
import org.apache.cxf.message.Message;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;

import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.unicore.security.wsutil.client.LogInMessageHandler;
import eu.unicore.security.wsutil.client.LogOutMessageHandler;
import eu.unicore.security.wsutil.client.UnicoreWSClientFactory;
import eu.unicore.security.wsutil.client.WSClientFactory;
import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * @author schuller
 * @author golbi
 */
public abstract class AbstractTestBase extends TestCase
{

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
		factory.setServiceName(new QName("unicore.eu",serviceName));
		
		List<Interceptor<? extends Message>> s = factory.getInInterceptors();
		addHandlers(s);
		factory.getOutInterceptors().add(new ConditionalGetServerOutHandler());
		factory.getOutInterceptors().add(new SessionIDServerOutHandler());
		factory.getOutInterceptors().add(new LogOutMessageHandler());
		factory.create();
	}

	protected void addHandlers(List<Interceptor<? extends Message>> s)throws Exception{
		SecuritySessionStore sesStore = new SecuritySessionStore();
		AuthInHandler authHandler = new AuthInHandler(true, true, true, null, sesStore);
		authHandler.addUserAttributeHandler(new SimpleSecurityServiceImpl.SimpleUserAttributeHandler());
		DSigParseInHandler parseHandler = new DSigParseInHandler(null);
		DSigSecurityInHandler dsigHandler = new DSigSecurityInHandler(null);
		AdditionalInHandler addHandler = new AdditionalInHandler();
		ETDInHandler etdHandler=new ETDInHandler(null, new KeystoreCertChainValidator(
				MockSecurityConfig.KS,
				MockSecurityConfig.KS_PASSWD.toCharArray(),
				"JKS", -1));
		SecuritySessionCreateInHandler sessionHandler = new SecuritySessionCreateInHandler(sesStore);
		
		s.add(authHandler);
		s.add(parseHandler);
		s.add(dsigHandler);
		s.add(addHandler);
		s.add(etdHandler);
		s.add(sessionHandler);
		s.add(new LogInMessageHandler());
		s.add(new ConditionalGetServerInHandler());
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
		String addr="https://localhost:" + (JettyServer.PORT) + "/services/" 
				+ serviceName;
		return getWSClientFactory(sec).createPlainWSProxy(SimpleSecurityService.class, addr);
	}
	
	protected SimpleSecurityService makePlainProxy(IClientConfiguration sec) throws Exception
	{
		String addr="http://localhost:" + (JettyServer.PORT+1) + "/services/" 
				+ serviceName;
		return getWSClientFactory(sec).createPlainWSProxy(SimpleSecurityService.class, addr);
	}


	protected SimpleSecurityService makeSecuredProxy(IClientConfiguration sec) throws Exception
	{
		String addr="https://localhost:" + (JettyServer.PORT) + "/services/" 
				+ serviceName;
		return new UnicoreWSClientFactory(sec).createPlainWSProxy(SimpleSecurityService.class, addr);
	}

	protected WSClientFactory getWSClientFactory(IClientConfiguration sec){
		return new WSClientFactory(sec);
	}
}
