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
package eu.openanalytics.containerproxy.backend;

import javax.inject.Inject;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import eu.openanalytics.containerproxy.backend.aws.fargate.AwsFargateBackend;
import eu.openanalytics.containerproxy.backend.docker.DockerEngineBackend;
import eu.openanalytics.containerproxy.backend.docker.DockerSwarmBackend;
import eu.openanalytics.containerproxy.backend.kubernetes.KubernetesBackend;

@Service
public class ContainerBackendFactory extends AbstractFactoryBean<IContainerBackend> implements ApplicationContextAware {
	
	private static final String PROPERTY_CONTAINER_BACKEND = "proxy.container-backend";
	protected final Logger log = LogManager.getLogger(getClass());
	
	private enum ContainerBackend {
		
		DockerEngine("docker", DockerEngineBackend.class),
		DockerSwarm("docker-swarm", DockerSwarmBackend.class),
		Kubernetes("kubernetes", KubernetesBackend.class),
		AwsFargate("aws-ecs-fargate", AwsFargateBackend.class);
		
		private String name;
		private Class<? extends IContainerBackend> type;
		
		private ContainerBackend(String name, Class<? extends IContainerBackend> type) {
			this.name = name;
			this.type = type;
		}
		
		public static IContainerBackend createFor(String name) throws Exception {
			for (ContainerBackend cb: values()) {
				if (cb.name.equalsIgnoreCase(name)) return cb.type.newInstance();
			}
			return DockerEngine.type.newInstance();
		}
	}
	
	private ApplicationContext applicationContext;
	
	@Inject
	protected Environment environment;
	
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}
	
	@Override
	public Class<?> getObjectType() {
		return IContainerBackend.class;
	}

	@Override
	protected IContainerBackend createInstance() throws Exception {		
		String backendName = environment.getProperty(PROPERTY_CONTAINER_BACKEND);
		log.info("VMC ------ BACKEND NAME: " + backendName);
		IContainerBackend backend = ContainerBackend.createFor(backendName);
		applicationContext.getAutowireCapableBeanFactory().autowireBean(backend);
		backend.initialize();
		return backend;
	}
}
