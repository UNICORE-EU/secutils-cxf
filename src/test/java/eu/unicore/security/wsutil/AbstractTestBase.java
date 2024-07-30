package eu.unicore.security.wsutil;

import java.util.List;

import javax.xml.namespace.QName;

import org.apache.cxf.interceptor.Interceptor;
import org.apache.cxf.jaxws.JaxWsServerFactoryBean;
import org.apache.cxf.message.Message;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.unicore.samly2.trust.TruststoreBasedSamlTrustChecker;
import eu.unicore.security.wsutil.client.WSClientFactory;
import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * @author schuller
 * @author golbi
 */
public abstract class AbstractTestBase {

	protected JettyServer jetty; 

	protected String serviceName="SimpleSecurityService";
	protected QName serviceQName=new QName("foo", serviceName);
	
	@BeforeEach
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
		factory.create();
	}

	protected void addHandlers(List<Interceptor<? extends Message>> s)throws Exception{
		KeystoreCertChainValidator trustedIssuersStore = new KeystoreCertChainValidator(
				"src/test/resources/certs/idp.jks", 
				"the!test".toCharArray(), "JKS", -1);
		AuthInHandler authHandler = new AuthInHandler(true, true, true, null);
		authHandler.addUserAttributeHandler(new SimpleSecurityServiceImpl.SimpleUserAttributeHandler());
		TruststoreBasedSamlTrustChecker samlTrustChecker = new TruststoreBasedSamlTrustChecker(
				trustedIssuersStore);
		authHandler.enableSamlAuthentication(MockSecurityConfig.SERVER_CRED.getSubjectName(), 
				jetty.getUrls()[0].toExternalForm(), 
				samlTrustChecker, 0);
		
		s.add(authHandler);
	}
	
	@AfterEach
	protected void tearDown() throws Exception
	{
		jetty.stop();
	}

	protected SimpleSecurityService makeProxy(IClientConfiguration sec) throws Exception
	{
		return getWSClientFactory(sec).createPlainWSProxy(SimpleSecurityService.class, getAddress());
	}
	
	protected SimpleSecurityService makePlainProxy(IClientConfiguration sec) throws Exception
	{
		String addr="http://localhost:" + (JettyServer.PORT+1) + "/services/" 
				+ serviceName;
		return getWSClientFactory(sec).createPlainWSProxy(SimpleSecurityService.class, addr);
	}


	protected SimpleSecurityService makeSecuredProxy(IClientConfiguration sec) throws Exception
	{
		return new WSClientFactory(sec).createPlainWSProxy(SimpleSecurityService.class, getAddress());
	}

	protected WSClientFactory getWSClientFactory(IClientConfiguration sec){
		return new WSClientFactory(sec);
	}
	
	protected String getAddress()
	{
		return "https://localhost:" + (JettyServer.PORT) + "/services/" 
				+ serviceName;
	}
}
