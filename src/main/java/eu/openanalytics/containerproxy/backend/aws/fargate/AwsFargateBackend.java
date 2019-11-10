/**
 * ContainerProxy
 *
 * Copyright (C) 2016-2019 Open Analytics
 *
 * ===========================================================================
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License as published by
 * The Apache Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License
 * along with this program.  If not, see <http://www.apache.org/licenses/>
 */
package eu.openanalytics.containerproxy.backend.aws.fargate;

import java.net.URI;

import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.DescribeNetworkInterfacesRequest;
import com.amazonaws.services.ec2.model.DescribeNetworkInterfacesResult;
import com.amazonaws.services.ec2.model.NetworkInterface;
import com.amazonaws.services.ecs.AmazonECS;
import com.amazonaws.services.ecs.AmazonECSClientBuilder;
import com.amazonaws.services.ecs.model.Attachment;
import com.amazonaws.services.ecs.model.AwsVpcConfiguration;
import com.amazonaws.services.ecs.model.ContainerOverride;
import com.amazonaws.services.ecs.model.DescribeTasksRequest;
import com.amazonaws.services.ecs.model.DescribeTasksResult;
import com.amazonaws.services.ecs.model.KeyValuePair;
import com.amazonaws.services.ecs.model.LaunchType;
import com.amazonaws.services.ecs.model.NetworkConfiguration;
import com.amazonaws.services.ecs.model.RunTaskRequest;
import com.amazonaws.services.ecs.model.RunTaskResult;
import com.amazonaws.services.ecs.model.StopTaskRequest;
import com.amazonaws.services.ecs.model.StopTaskResult;
import com.amazonaws.services.ecs.model.Task;
import com.amazonaws.services.ecs.model.TaskOverride;
import com.amazonaws.waiters.WaiterParameters;

import eu.openanalytics.containerproxy.ContainerProxyException;
import eu.openanalytics.containerproxy.backend.AbstractContainerBackend;
import eu.openanalytics.containerproxy.model.runtime.Container;
import eu.openanalytics.containerproxy.model.runtime.Proxy;
import eu.openanalytics.containerproxy.model.spec.ContainerSpec;

public class AwsFargateBackend extends AbstractContainerBackend{
	
	private static final String PROPERTY_PREFIX = "proxy.aws-ecs-fargate.";
	
	protected static final String PROPERTY_AWS_ECS_CLUSTER = "cluster";
	protected static final String PROPERTY_AWS_ECS_SECURITY_GROUP = "security-group";
	protected static final String PROPERTY_AWS_ECS_SUBNET = "subnet";
	protected static final String PROPERTY_AWS_ECS_USE_PUBLIC_IP = "use-public-ip";
	
	private String cluster;
	private String securityGroup;
	private String subnet;
	private Boolean usePublicIp;
	
	
	@Override
	public void initialize() throws ContainerProxyException {
		log.info("AWS - Inicializando o client");
		usePublicIp = Boolean.valueOf(getProperty(PROPERTY_AWS_ECS_USE_PUBLIC_IP, "false"));
		cluster = String.valueOf(getProperty(PROPERTY_AWS_ECS_CLUSTER,""));
		securityGroup = String.valueOf(getProperty(PROPERTY_AWS_ECS_SECURITY_GROUP,""));
		subnet = String.valueOf(getProperty(PROPERTY_AWS_ECS_SUBNET,""));		 
	}
	
	@Override
	protected Container startContainer(ContainerSpec spec, Proxy proxy) throws Exception {
		AmazonECS ecs_client = AmazonECSClientBuilder.standard().build();
		AmazonEC2 ec2_client = AmazonEC2ClientBuilder.standard().build();
		
		
		

		log.info("AWS - Start Container");
		log.info("AWS - Cluster: " + cluster);
		Container container = new Container();
		container.setSpec(spec);
		
		String image = spec.getImage();
		log.info("AWS - Image: " + image);
		log.info("AWS - CMD: " + spec.getCmd().toString());
				
		// TaskOverride overrides = buildTaskOverride(spec);
		RunTaskRequest request = new RunTaskRequest()
				.withCount(1)
				// .withOverrides(overrides)
				.withLaunchType(LaunchType.FARGATE)
				.withCluster(cluster)
				.withNetworkConfiguration(computeNetworkConfiguration())
				.withTaskDefinition(image);
		 RunTaskResult response = ecs_client.runTask(request);
		
		for (Task task: response.getTasks()) {		
			container.setId(task.getTaskArn());
		}
		
		DescribeTasksRequest describeTasksRequest = new DescribeTasksRequest()
				.withTasks(container.getId())
				.withCluster(cluster);
		
		log.info("AWS - Inicio waiter");
		ecs_client.waiters().tasksRunning().run(
				new WaiterParameters<DescribeTasksRequest>()
				.withRequest(describeTasksRequest)
				);
		log.info("AWS - Fim waiter");
		

		DescribeTasksResult describeTasksResponse = ecs_client.describeTasks(describeTasksRequest);
		
		log.info("AWS respo: " + describeTasksResponse);
		
		for (Task task: describeTasksResponse.getTasks()) {
			container.setId(task.getTaskArn());
			for (Attachment a: task.getAttachments()) {
				for (KeyValuePair d: a.getDetails()) {
					if (d.getName().equals("networkInterfaceId")) {
						String eniId = d.getValue();
						DescribeNetworkInterfacesRequest describeNetworkInterfacesRequest = new DescribeNetworkInterfacesRequest()
								.withNetworkInterfaceIds(eniId);
						DescribeNetworkInterfacesResult describeNetworkInterfacesResponse = ec2_client.describeNetworkInterfaces(describeNetworkInterfacesRequest);
						for (NetworkInterface n: describeNetworkInterfacesResponse.getNetworkInterfaces()) {
							String privateIp = n.getPrivateDnsName();
							log.info("AWS Private IP: " + privateIp);
							String publicIp = n.getAssociation().getPublicDnsName();							
							log.info("AWS Public IP: " + publicIp);
							String host;
							if (isUsePublicIp()) {
								host = publicIp;
							} else {
								host = privateIp;
							}
							for (String mappingKey: spec.getPortMapping().keySet()) {
								int containerPort = spec.getPortMapping().get(mappingKey);
								String mapping = mappingStrategy.createMapping(mappingKey, container, proxy);
								URI target = new URI(String.format("%s://%s:%s",  "http", host, containerPort));
								proxy.getTargets().put(mapping, target);
							}
						}
					}
				}
			}
		}
		return container;
	}

//	private TaskOverride buildTaskOverride(ContainerSpec spec) {
//		ContainerOverride containerOverrides = new ContainerOverride()				
//				.withCommand(spec.getCmd());
//		TaskOverride overrides = new TaskOverride()
//				.withContainerOverrides(containerOverrides);
//		return overrides;
//	}

	
	@Override
	protected void doStopProxy(Proxy proxy) throws Exception {
		log.info("AWS - Sending STOP to task");
		AmazonECS ecs_client = AmazonECSClientBuilder.standard().build();		
		for (Container container: proxy.getContainers()) {
			StopTaskRequest request = new StopTaskRequest()
					.withCluster(cluster)
					.withTask(container.getId());
			StopTaskResult response = ecs_client.stopTask(request);
			log.info("AWS - Response: " + response);
		}
		
	}

	@Override
	protected String getPropertyPrefix() {
		return PROPERTY_PREFIX;
	}
	
	protected NetworkConfiguration computeNetworkConfiguration() {
		AwsVpcConfiguration awsvpcConfiguration = new AwsVpcConfiguration()				
				.withAssignPublicIp(assignPublicIp())
				.withSecurityGroups(securityGroup)
				.withSubnets(subnet);
		NetworkConfiguration config = new NetworkConfiguration()
				.withAwsvpcConfiguration(awsvpcConfiguration);
		return config;
	}
	
	protected boolean isUsePublicIp() {
		return usePublicIp;
	}
	
	protected String assignPublicIp() {
		if (isUsePublicIp()) {
			return "ENABLED";
		}
		else {
			return "DISABLED";
		}
	}
	
}
