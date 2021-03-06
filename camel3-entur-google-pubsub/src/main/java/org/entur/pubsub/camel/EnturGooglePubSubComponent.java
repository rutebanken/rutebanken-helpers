package org.entur.pubsub.camel;

import com.google.cloud.spring.pubsub.core.PubSubTemplate;
import org.apache.camel.CamelContext;
import org.apache.camel.Endpoint;
import org.apache.camel.support.DefaultComponent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class EnturGooglePubSubComponent extends DefaultComponent {

    @Value("${spring.cloud.gcp.pubsub.project-id}")
    private String projectId;

    @Autowired
    private PubSubTemplate pubSubTemplate;

    public EnturGooglePubSubComponent() {
        super();
    }

    public EnturGooglePubSubComponent(CamelContext context) {
        super(context);
    }


    @Override
    protected Endpoint createEndpoint(String uri, String remaining, Map<String, Object> parameters) throws
            Exception {

        EnturGooglePubSubEndpoint pubsubEndpoint = new EnturGooglePubSubEndpoint(uri, this, pubSubTemplate);
        pubsubEndpoint.setDestinationName(remaining);
        pubsubEndpoint.setProjectId(projectId);

        setProperties(pubsubEndpoint, parameters);

        return pubsubEndpoint;
    }
}
