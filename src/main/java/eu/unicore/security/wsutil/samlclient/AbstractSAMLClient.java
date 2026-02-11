package eu.unicore.security.wsutil.samlclient;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.trust.SamlTrustChecker;
import eu.unicore.security.wsutil.client.WSClientFactory;
import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * This class provides a base for SAML client implementations which use
 * SOAP binding. It setups the client factory.
 *
 * @author K. Benedyczak
 */
public abstract class AbstractSAMLClient
{
	protected String address;
	protected NameID localIssuer = null;
	protected WSClientFactory factory;
	protected SamlTrustChecker trustChecker;
	protected transient X509CertChainValidator validator;
	
	/**
	 * @param address
	 * @param secProv
	 * @param trustChecker
	 * @throws MalformedURLException
	 */
	protected AbstractSAMLClient(String address, IClientConfiguration secProv, SamlTrustChecker trustChecker) 
		throws MalformedURLException
	{
		this(address, secProv, (NameID)null, trustChecker);
	}

	/**
	 * @return local issuer as created from the DN, or null if unknown
	 */
	protected NameID getLocalIssuer()
	{
		return localIssuer;
	}
	
	/**
	 * @return issuer generated from the local identity.
	 */
	protected NameID generateIssuer(IClientConfiguration secCfg)
	{
		X509Certificate[] certificateC = null;
		if (secCfg.getCredential() != null)
			certificateC = secCfg.getCredential().getCertificateChain();
		if (certificateC == null || certificateC.length == 0)
			return null;
		return new NameID(certificateC[0].getSubjectX500Principal().getName(), 
			SAMLConstants.NFORMAT_DN);
	}
	
	@SuppressWarnings("unused")
	protected AbstractSAMLClient(String address, IClientConfiguration secCfg, NameID issuer, 
			SamlTrustChecker trustChecker) throws MalformedURLException
	{
		this.trustChecker = trustChecker;
		this.validator = secCfg.getValidator();
		new URL(address);
		this.address = address;
		factory = new WSClientFactory(secCfg);
		localIssuer = generateIssuer(secCfg);
	}
}
