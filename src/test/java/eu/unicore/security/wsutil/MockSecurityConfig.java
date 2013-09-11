/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 28, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.unicore.util.httpclient.DefaultClientConfiguration;


/**
 * @author K. Benedyczak
 */
public class MockSecurityConfig extends DefaultClientConfiguration
{
	public static KeystoreCredential IDP_CRED;
	public static KeystoreCredential CLIENT1_CRED;
	public static KeystoreCredential CLIENT2_CRED;
	public static KeystoreCredential WRONGCLIENT_CRED;
	public static KeystoreCredential SERVER_CRED;
	public static KeystoreCredential GW_CRED;
	
	public static X509CertChainValidatorExt VALIDATOR;
	
	static 
	{
		try
		{
			IDP_CRED = new KeystoreCredential("src/test/resources/certs/idp.jks", 
					"the!test".toCharArray(), 
					"the!test".toCharArray(), null, "JKS");
			CLIENT1_CRED = new KeystoreCredential("src/test/resources/certs/client1.jks", 
					"the!test".toCharArray(), 
					"the!test".toCharArray(), null, "JKS");
			CLIENT2_CRED = new KeystoreCredential("src/test/resources/certs/client2.jks", 
					"the!test".toCharArray(), 
					"the!test".toCharArray(), null, "JKS");
			WRONGCLIENT_CRED = new KeystoreCredential("src/test/resources/certs/clientWrong.jks", 
					"the!client".toCharArray(), 
					"the!client".toCharArray(), "mykey", "JKS");
			SERVER_CRED = new KeystoreCredential("src/test/resources/certs/server.jks", 
					"the!test".toCharArray(), 
					"the!test".toCharArray(), null, "JKS");
			GW_CRED = new KeystoreCredential("src/test/resources/certs/gateway.jks", 
					"the!gateway".toCharArray(), 
					"the!gateway".toCharArray(), null, "JKS");
			VALIDATOR = new KeystoreCertChainValidator("src/test/resources/certs/dummycatruststore.jks",
					"the!ca".toCharArray(), "JKS", -1);
		} catch (Exception e)
		{
			e.printStackTrace();
		}
	}
	
	public static final String HTTP_PASSWD = "123";
	public static final String HTTP_USER = "qwer";
	
	public MockSecurityConfig(boolean doHTTPAuthN,
			boolean doSSLAuthN, boolean useUser1) throws Exception
	{
		this(doHTTPAuthN, doSSLAuthN, useUser1 ? CLIENT1_CRED : CLIENT2_CRED);
	}

	public MockSecurityConfig(boolean doHTTPAuthN,
			boolean doSSLAuthN, X509Credential identity) throws Exception
	{
		setSslEnabled(true);
		setDoSignMessage(true);
		setHttpAuthn(doHTTPAuthN);
		setSslAuthn(doSSLAuthN);
		setHttpPassword(HTTP_PASSWD);
		setHttpUser(HTTP_USER);
		setCredential(identity);
		setValidator(VALIDATOR);
		setUseSecuritySessions(false);
	}

	public MockSecurityConfig clone()
	{
		try
		{
			MockSecurityConfig ret = new MockSecurityConfig(doHttpAuthn(), doSSLAuthn(), getCredential());
			ret.setClassLoader(getClassLoader());
			ret.setDoSignMessage(doSignMessage());
			ret.setEtdSettings(getETDSettings().clone());
			ret.setExtraSecurityTokens(getExtraSecurityTokens());
			ret.setHttpClientProperties(getHttpClientProperties());
			ret.setInHandlerClassNames(getInHandlerClassNames());
			ret.setOutHandlerClassNames(getOutHandlerClassNames());
			ret.setUseSecuritySessions(useSecuritySessions());
			ret.setSessionIDProvider(getSessionIDProvider());
			return ret;
		} catch (Exception e)
		{
			throw new RuntimeException("Can't clone", e);
		}
	}

	@Override
	public String[] getOutHandlerClassNames()
	{
		return new String[] {AdditionalOutHandler.class.getName()};
	}

	@Override
	public String[] getInHandlerClassNames()
	{
		return new String[] {AdditionalInHandler.class.getName()};
	}

	public String getCertDN() throws Exception
	{
		return getCredential().getCertificate().getSubjectX500Principal().getName();
		
	}
}
