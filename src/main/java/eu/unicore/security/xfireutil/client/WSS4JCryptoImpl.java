/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.xfireutil.client;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.CredentialException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoBase;
import org.apache.ws.security.components.crypto.CryptoType;
import org.bouncycastle.util.Arrays;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.X500NameUtils;


/**
 * Custom implementation of the {@link Crypto} interface, uses caNl.
 * The implementations available in the library require everything in keystores,
 * on disk and usage of standard validation algorithm from JSSE.
 * <p>
 * Currently this class offers only a minimal implementation providing a private credential,
 * so it is useful for generation of digital signatures only. It can be easily 
 * extended in future to also support validation if needed.
 * 
 * @author K. Benedyczak
 */
public class WSS4JCryptoImpl extends CryptoBase implements Crypto
{
	private X509Credential credential;
	
	public WSS4JCryptoImpl(X509Credential credential) throws CredentialException, IOException
	{
		this.credential = credential;
	}

	private void checkCerts(X509Certificate arg) throws WSSecurityException 
	{
		if (!Arrays.areEqual(credential.getCertificate().getSignature(), arg.getSignature()))
			throw new WSSecurityException(WSS4JCryptoImpl.class + 
				" was asked about data of certificate " +
				"which is not associated with credential: " + arg.toString());
	}
	
	@Override
	public PrivateKey getPrivateKey(X509Certificate arg0, CallbackHandler arg1) throws WSSecurityException
	{
		checkCerts(arg0);
		return credential.getKey();
	}

	@Override
	public PrivateKey getPrivateKey(String arg0, String arg1) throws WSSecurityException
	{
		if (!credential.getKeyAlias().equals(arg0))
			throw new WSSecurityException(WSS4JCryptoImpl.class + 
				" was asked about private key with wrong alias: " + arg0);
			
		return credential.getKey();
	}

	@Override
	public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException
	{
		if (cryptoType == null)
			return null;
		CryptoType.TYPE type = cryptoType.getType();
		switch (type)
		{
		case ISSUER_SERIAL:
			if (!X500NameUtils.equal(credential.getCertificate().getIssuerX500Principal(),
					cryptoType.getIssuer()))
				throw new WSSecurityException(WSS4JCryptoImpl.class + 
					" was asked about cert chain with wrong issuer: " + cryptoType.getIssuer());
				
			if (!cryptoType.getSerial().equals(credential.getCertificate().getSerialNumber()))
				throw new WSSecurityException(WSS4JCryptoImpl.class + 
					" was asked about cert chain with wrong serial: " + cryptoType.getSerial());
			break;
		case THUMBPRINT_SHA1:
			throw new WSSecurityException(WSS4JCryptoImpl.class + 
				" not implemented: THUMB_SHA1");
			//break;
		case SKI_BYTES:
			throw new WSSecurityException(WSS4JCryptoImpl.class + 
					" not implemented: SKI_BYTES");
			//break;
		case SUBJECT_DN:
			if (!X500NameUtils.equal(credential.getCertificate().getSubjectX500Principal(), 
					cryptoType.getSubjectDN()))
				throw new WSSecurityException(WSS4JCryptoImpl.class + 
					" was asked about cert chain with wrong subject: " + cryptoType.getSubjectDN());
			break;
		case ALIAS:
			if (cryptoType.getAlias() == null)
				throw new WSSecurityException(WSS4JCryptoImpl.class + 
						" was asked about cert chain with null alias");
			if (!cryptoType.getAlias().equals(credential.getKeyAlias()))
				throw new WSSecurityException(WSS4JCryptoImpl.class + 
					" was asked about cert chain with wrong alias: " + cryptoType.getAlias());
			break;
		}
		return credential.getCertificateChain();
	}

	@Override
	public String getX509Identifier(X509Certificate arg0) throws WSSecurityException
	{
		checkCerts(arg0);		
		return credential.getKeyAlias();
	}

	@Override
	public boolean verifyTrust(X509Certificate[] arg0) throws WSSecurityException
	{
		throw new WSSecurityException(WSS4JCryptoImpl.class + 
				" not implemented: verifyTrust(X509Certificate[])");
	}

	@Override
	public boolean verifyTrust(PublicKey arg0) throws WSSecurityException
	{
		throw new WSSecurityException(WSS4JCryptoImpl.class + 
				" not implemented: verifyTrust(PublicKey)");
	}

	@Override
	public boolean verifyTrust(X509Certificate[] arg0, boolean arg1) throws WSSecurityException
	{
		throw new WSSecurityException(WSS4JCryptoImpl.class + 
				" not implemented: verifyTrust(X509Certificate[], boolean)");
	}

}
