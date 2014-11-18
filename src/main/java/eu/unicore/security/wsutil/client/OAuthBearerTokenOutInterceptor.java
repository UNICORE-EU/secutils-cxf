package eu.unicore.security.wsutil.client;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.cxf.helpers.CastUtils;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;

import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * if present, the OAuth2 Bearer token is placed into a HTTP Authorization header
 * 
 * @author schuller
 */
public class OAuthBearerTokenOutInterceptor extends AbstractPhaseInterceptor<Message> implements Configurable {

	/**
	 * key for putting the Bearer token into the {@link IClientConfiguration#getExtraSecurityTokens()}
	 */
	public static final String TOKEN_KEY = "____OAUTH2_BEARER_TOKEN";
	
	private String token;
	
	public OAuthBearerTokenOutInterceptor() {
		super(Phase.WRITE);
	}

	public void handleMessage(Message message) throws Fault {
		if(token!=null){
			Map<String, List<String>> headers = CastUtils.cast((Map<?,?>)message.get(Message.PROTOCOL_HEADERS));
			headers.put("Authorization", Collections.singletonList("Bearer " + token));
		}
	}

	@Override
	public void configure(IClientConfiguration properties) {
		Map<String, Object> t = properties.getExtraSecurityTokens();
		if(t!=null){
			token = (String)t.get(TOKEN_KEY);
		}
	}

}
