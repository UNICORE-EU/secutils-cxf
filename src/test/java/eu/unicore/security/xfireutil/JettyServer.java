/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Aug 8, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil;

import java.net.URL;

import javax.security.auth.x500.X500Principal;

import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;

import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.unicore.security.util.ConfigurationException;
import eu.unicore.security.util.client.DefaultClientConfiguration;
import eu.unicore.security.util.jetty.JettyLogger;
import eu.unicore.security.util.jetty.JettyProperties;
import eu.unicore.security.util.jetty.JettyServerBase;



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
						new KeystoreCertChainValidator(KS, 
								KS_PWD.toCharArray(), 
								"JKS",	-1),
						new KeystoreCredential(KS, 
								KS_PWD.toCharArray(),
								KS_PWD.toCharArray(),
								null,
								"JKS")),
				getJettyProperties(), 
				JettyLogger.class);
		
		this.servlet=servlet;
		initServer();
	}

	private static JettyProperties getJettyProperties() 
	{
		JettyProperties ret = getSimpleTestSettings();
		ret.setProperty(JettyProperties.REQUIRE_CLIENT_AUTHN, "false");
		return ret;
	}
	
	@Override
	protected Context createRootContext() throws ConfigurationException
	{
		Context root=new Context(getServer(), "/", Context.SESSIONS);
		root.addServlet(new ServletHolder(servlet), "/services/*");
		return root;
	}
}
