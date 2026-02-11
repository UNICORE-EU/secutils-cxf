package eu.unicore.security.wsutil.cxf;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.logging.Logger;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.validation.Schema;

import org.apache.cxf.common.i18n.Message;
import org.apache.cxf.common.logging.LogUtils;
import org.apache.cxf.databinding.DataReader;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Attachment;
import org.apache.cxf.service.model.MessagePartInfo;
import org.apache.xmlbeans.SchemaType;
import org.apache.xmlbeans.XmlAnySimpleType;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;


public class DataReaderImpl implements DataReader<XMLStreamReader> {
    private static final Logger LOG = LogUtils.getLogger(XmlBeansDataBinding.class);
    private boolean validate;
    
    public DataReaderImpl() {
    }

    public Object read(XMLStreamReader input) {
        return read(null, input);
    }

    public Object read(MessagePartInfo part, XMLStreamReader reader) {
        Class<?> typeClass = part.getTypeClass();
        boolean unwrap = false;
        if (!XmlObject.class.isAssignableFrom(typeClass)) {
            typeClass = (Class<?>)part.getProperty(XmlAnySimpleType.class.getName());
            unwrap = true;
        }
        return doRead(reader,
                      part.getTypeClass(), 
                      typeClass, 
                      (SchemaType)part.getProperty(SchemaType.class.getName()), 
                      unwrap);
    }

    public Object read(QName name, XMLStreamReader reader, Class<?> typeClass) {
        SchemaType st = null;
        try {
            Field f = typeClass.getField("type");
            if (Modifier.isStatic(f.getModifiers())) {
                st = (SchemaType)f.get(null);
            }
        } catch (Exception es) {
            es.printStackTrace();
            return null;
        }
        
        return doRead(reader,
                      typeClass, 
                      typeClass, 
                      st, 
                      false);
    }

    Object doRead(XMLStreamReader reader, Class<?> partTypeClass, 
                          Class<?> typeClass, SchemaType st, boolean unwrap) {
        boolean isOutClass = false;
        Class<?> encClass = typeClass.getEnclosingClass();
        if (encClass != null) {
            typeClass = encClass;
            isOutClass = true;
        }
        Field c = null;
        Object obj = null;
        try {
        	c = typeClass.getDeclaredField("Factory");
        	Object factory = c.get(typeClass);
        	Class<?> factoryClass = c.get(typeClass).getClass();
        	XmlOptions options = new XmlOptions();
        	if (validate) {
        		options.setValidateOnSet();
        	}
        	if (st != null && !st.isDocumentType() && !isOutClass) {
        		options.setLoadReplaceDocumentElement(null);
        	}
        	Method meth = factoryClass.getMethod("parse", XMLStreamReader.class, XmlOptions.class);
        	obj = meth.invoke(factory, reader, options);                    
        } catch (Exception e) {
        	throw new Fault(new Message("UNMARSHAL_ERROR", LOG, partTypeClass, e));
        }

        if (unwrap && obj != null) {
            try {
                Class<?> tc = partTypeClass; 
                String methName;
                if (tc.equals(Integer.TYPE) || tc.equals(Integer.class)) {
                    methName = "getIntValue";
                } else if (tc.equals(byte[].class)) {
                    methName = "byteArrayValue";
                } else {
                    String tp = tc.getSimpleName();
                    tp = Character.toUpperCase(tp.charAt(0)) + tp.substring(1);
                    methName = "get" + tp + "Value";
                }
                Method m = obj.getClass().getMethod(methName);
                obj = m.invoke(obj);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (isOutClass) {
            for (Method m : encClass.getDeclaredMethods()) {
                if (m.getName().startsWith("get")
                    && m.getParameterTypes().length == 0
                    && m.getReturnType().equals(partTypeClass)) {
                    try {
                        obj = m.invoke(obj);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        if (reader.getEventType() == XMLStreamReader.END_ELEMENT) {
            try {
                reader.next();
            } catch (XMLStreamException e) {
                throw new RuntimeException(e);
            }
        }
        return obj;
    }
    
    public void setAttachments(Collection<Attachment> attachments) {
    }

    public void setProperty(String prop, Object value) {
    }

    public void setSchema(Schema s) {
        validate = s != null;
    }
}
