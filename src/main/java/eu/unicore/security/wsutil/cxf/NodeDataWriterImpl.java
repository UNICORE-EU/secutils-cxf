package eu.unicore.security.wsutil.cxf;


import java.util.Collection;
import javax.xml.validation.Schema;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.cxf.databinding.DataWriter;
import org.apache.cxf.message.Attachment;
import org.apache.cxf.service.model.MessagePartInfo;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;

public class NodeDataWriterImpl implements DataWriter<Node> {
    DataWriterImpl writer;
    
    public NodeDataWriterImpl() {
        writer = new DataWriterImpl();
    }
    
    public void write(Object obj, Node output) {
        write(obj, null, output);
    }
    
    public void write(Object obj, MessagePartInfo part, Node output) {
        W3CDOMStreamWriter domWriter = new W3CDOMStreamWriter((Element)output);
        writer.write(obj, part, domWriter);
    }

    public void setAttachments(Collection<Attachment> attachments) {
        writer.setAttachments(attachments);
    }

    public void setProperty(String key, Object value) {
        writer.setProperty(key, value);
    }

    public void setSchema(Schema s) {
        writer.setSchema(s);
    }
}
