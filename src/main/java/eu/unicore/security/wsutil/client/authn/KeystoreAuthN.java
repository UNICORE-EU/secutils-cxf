package eu.unicore.security.wsutil.client.authn;

import java.util.Properties;

import eu.unicore.security.canl.CredentialProperties;
import eu.unicore.security.canl.PasswordCallback;
import eu.unicore.security.canl.TruststoreProperties;
import eu.unicore.util.httpclient.ClientProperties;
import eu.unicore.util.httpclient.DefaultClientConfiguration;

/**
 * Classic UNICORE 6 authentication method: local X.509 certificate is used, 
 * configured using the standard "credential.*" and "truststore.*" properties<br/>
 * <p>
 * The class is thread safe
 * @author schuller
 */
public class KeystoreAuthN extends PropertiesBasedAuthenticationProvider implements AuthenticationProvider {

	public static final String X509="X509";
	
	public KeystoreAuthN(Properties properties, PasswordCallback passwordCallback)
	{
		super(properties, passwordCallback);
	}

	protected KeystoreAuthN()
	{
	}
	
	@Override
	public String getName() {
		return X509;
	}

	@Override
	public String getDescription() {
		return "Uses a local keystore and optional truststore file.";
	}

	@Override
	public DefaultClientConfiguration getClientConfiguration(String targetAddress,
			String targetDn, DelegationSpecification delegate) throws Exception
	{
		ClientProperties sp=new ClientProperties(properties, truststorePasswordCallback, 
				TruststoreProperties.DEFAULT_PREFIX, 
				CredentialProperties.DEFAULT_PREFIX, ClientProperties.DEFAULT_PREFIX);
		applyLocalDelegation(sp, targetDn, delegate);
		return sp;
	}

	@Override
	public String getUsage()
	{
		StringBuilder ret = new StringBuilder();
		ret.append("The following properties can be used in the UCC preference file " +
				"to configure the X509 authentication. Many of these are optional. Refer to the " +
				"manual and/or the example files.\n");
		ret.append("\nFor configuring your credential:\n");
		ret.append(getMeta(CredentialProperties.class, CredentialProperties.DEFAULT_PREFIX));

		ret.append("\nFor configuring your trusted CAs and certificates:\n");
		ret.append(getMeta(TruststoreProperties.class, TruststoreProperties.DEFAULT_PREFIX));
		return ret.toString();
	}
}
