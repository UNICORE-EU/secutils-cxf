package eu.unicore.security.wsutil.client;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;

public class CleanupHandler extends AbstractPhaseInterceptor<Message> {

	private final Client client;

	public CleanupHandler(Client client)
	{
		super(Phase.POST_LOGICAL_ENDING);
		this.client = client;
	}

	@Override
	public void handleMessage(Message message) throws Fault{
		client.getResponseContext().clear();
	}

	@Override
	public void handleFault(Message message){
		client.getResponseContext().clear();
	}
}
