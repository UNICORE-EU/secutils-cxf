package eu.unicore.security.wsutil;

import java.net.URL;

import javax.security.auth.x500.X500Principal;

import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Handler;

import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.jetty.HttpServerProperties;
import eu.unicore.util.jetty.JettyServerBase;



/**
 * Test Jetty server implementation.
 * @author K. Benedyczak
 */
public class JettyServer extends JettyServerBase
{
	public static final int PORT = 65344;
	public static final String KS = "src/test/resources/conf/server.jks";
	public static final String KS_PWD = "the!server";
	public static final X500Principal SERVER_IDENTITY = new X500Principal(
			"CN=TestServer, OU=ICM, O=UW, L=Warsaw, ST=Unknown, C=PL");

	private final CXFNonSpringServlet servlet;
	
	public JettyServer(CXFNonSpringServlet servlet) throws Exception
	{
		super(new URL[] {new URL("https://localhost:" + PORT), 
				 new URL("http://localhost:" + (PORT+1))},  
				 new DefaultClientConfiguration(
						MockSecurityConfig.VALIDATOR,
						MockSecurityConfig.SERVER_CRED),
				getJettyProperties());
		
		this.servlet=servlet;
		initServer();
	}

	private static HttpServerProperties getJettyProperties() 
	{
		HttpServerProperties ret = HttpServerProperties.getSimpleTestSettings();
		ret.setProperty(HttpServerProperties.REQUIRE_CLIENT_AUTHN, "false");
		return ret;
	}

	@Override
	protected Handler createRootHandler() throws ConfigurationException
	{
		ServletContextHandler root = new ServletContextHandler("/", ServletContextHandler.SESSIONS);
		root.addServlet(new ServletHolder(servlet), "/services/*");
		return root;
	}
}
