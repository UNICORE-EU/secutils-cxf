package eu.unicore.security.wsutil.client.authn;

import java.util.Properties;

import eu.unicore.security.canl.CredentialProperties;
import eu.unicore.security.canl.PasswordCallback;
import eu.unicore.security.canl.TruststoreProperties;

/**
 * Authenticate with a local X.509 certificate, configured using the
 * standard "credential.*" and "truststore.*" properties<br/>
 *
 * The class is thread safe
 * @author schuller
 */
public class KeystoreAuthN extends PropertiesBasedAuthenticationProvider implements AuthenticationProvider {

	public KeystoreAuthN(Properties properties, PasswordCallback passwordCallback)
	{
		super(properties, passwordCallback);
	}

	protected KeystoreAuthN(){}

	@Override
	public String getName() {
		return "X509";
	}

	@Override
	public String getDescription() {
		return "Uses a local keystore and optional truststore.";
	}

	@Override
	public String getUsage()
	{
		StringBuilder ret = new StringBuilder();
		ret.append("The following properties can be used to configure the X509 authentication.");
		ret.append(" Many of these are optional. Refer to the manual and the example files.\n");
		ret.append("\nFor configuring your credential:\n");
		ret.append(getMeta(CredentialProperties.class, CredentialProperties.DEFAULT_PREFIX));
		ret.append("\nFor configuring your trusted CAs and certificates:\n");
		ret.append(getMeta(TruststoreProperties.class, TruststoreProperties.DEFAULT_PREFIX));
		return ret.toString();
	}
}
