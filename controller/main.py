"""
FortiWeb CRD Controller

Watches FortiWebIngress CRDs and configures FortiWeb WAF accordingly.
"""

import base64
import kopf
import kubernetes
import logging
from typing import Optional

from fortiweb_client import FortiWebClient, FortiWebConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_credentials(namespace: str, secret_name: str, secret_namespace: Optional[str] = None) -> dict:
    """Fetch FortiWeb credentials from Kubernetes secret."""
    api = kubernetes.client.CoreV1Api()
    ns = secret_namespace or namespace

    try:
        secret = api.read_namespaced_secret(secret_name, ns)
        return {
            "username": base64.b64decode(secret.data.get("username", "")).decode(),
            "password": base64.b64decode(secret.data.get("password", "")).decode(),
        }
    except kubernetes.client.ApiException as e:
        raise kopf.PermanentError(f"Failed to read credentials secret {ns}/{secret_name}: {e}")


def resolve_service_endpoints(
    service_name: str,
    service_namespace: str,
    port: int,
) -> list[dict]:
    """
    Resolve a Kubernetes service to its backend endpoints.
    Returns list of {ip, port} dicts.
    """
    api = kubernetes.client.CoreV1Api()

    try:
        # First check the service type
        service = api.read_namespaced_service(service_name, service_namespace)

        if service.spec.type == "ExternalName":
            # For ExternalName services, resolve the target service
            external_name = service.spec.external_name
            # Parse: service.namespace.svc.cluster.local
            if external_name.endswith(".svc.cluster.local"):
                parts = external_name.replace(".svc.cluster.local", "").split(".")
                if len(parts) == 2:
                    target_service, target_namespace = parts
                    logger.info(f"Resolving ExternalName {external_name} -> {target_namespace}/{target_service}")
                    return resolve_service_endpoints(target_service, target_namespace, port)

            # Can't resolve external DNS names to IPs
            raise kopf.TemporaryError(f"Cannot resolve ExternalName {external_name} to endpoints")

        # For ClusterIP/NodePort services, get endpoints
        endpoints = api.read_namespaced_endpoints(service_name, service_namespace)

        result = []
        for subset in endpoints.subsets or []:
            # Find the matching port
            target_port = port
            for ep_port in subset.ports or []:
                if ep_port.port == port or ep_port.name == str(port):
                    target_port = ep_port.port
                    break

            for address in subset.addresses or []:
                result.append({
                    "ip": address.ip,
                    "port": target_port,
                })

        if not result:
            raise kopf.TemporaryError(f"No ready endpoints for {service_namespace}/{service_name}")

        return result

    except kubernetes.client.ApiException as e:
        raise kopf.TemporaryError(f"Failed to resolve service {service_namespace}/{service_name}: {e}")


def generate_resource_name(cr_name: str, suffix: str) -> str:
    """Generate a FortiWeb resource name from CR name."""
    # FortiWeb has name length limits, keep it reasonable
    base = cr_name[:20] if len(cr_name) > 20 else cr_name
    return f"{base}-{suffix}"


@kopf.on.create("fortiweb.40docs.com", "v1", "fortiwebingresses")
@kopf.on.update("fortiweb.40docs.com", "v1", "fortiwebingresses")
async def reconcile_fortiweb_ingress(spec, name, namespace, status, patch, **kwargs):
    """
    Reconcile FortiWebIngress resource.

    Creates/updates:
    1. Virtual Server
    2. Server Pools (one per route)
    3. Content Routing Policies (one per route)
    4. Server Policy with all content routing rules wired in
    """
    logger.info(f"Reconciling FortiWebIngress {namespace}/{name}")

    # Update status to syncing
    patch.status["state"] = "Syncing"
    patch.status["message"] = "Starting reconciliation"

    # Get FortiWeb connection config
    fortiweb_spec = spec.get("fortiweb", {})
    credentials = get_credentials(
        namespace,
        fortiweb_spec.get("credentialsSecret"),
        fortiweb_spec.get("credentialsSecretNamespace"),
    )

    config = FortiWebConfig(
        address=fortiweb_spec.get("address"),
        username=credentials["username"],
        password=credentials["password"],
    )

    client = FortiWebClient(config)

    try:
        # Get configuration from spec
        vserver_spec = spec.get("virtualServer", {})
        policy_spec = spec.get("policy", {})
        routes = spec.get("routes", [])

        vserver_name = vserver_spec.get("name", name)
        policy_name = policy_spec.get("name", name)

        # Track created resources for status
        created_pools = []
        created_routing_rules = []

        # =====================================================================
        # Step 1: Create Virtual Server
        # =====================================================================
        logger.info(f"Creating virtual server: {vserver_name}")

        result = client.create_virtual_server(vserver_name)
        if result["status_code"] not in [200, 201, 500]:  # 500 might mean exists
            # Check if it already exists
            existing = client.get_virtual_server(vserver_name)
            if existing["status_code"] != 200:
                raise kopf.TemporaryError(f"Failed to create virtual server: {result}")

        # Add VIP to virtual server
        vip_result = client.add_vip_to_vserver(
            vserver_name=vserver_name,
            interface=vserver_spec.get("interface", "port1"),
            use_interface_ip=vserver_spec.get("useInterfaceIP", True),
            vip=vserver_spec.get("ip", ""),
        )
        logger.info(f"VIP configuration result: {vip_result}")

        # =====================================================================
        # Step 2: Create Server Pools and Content Routing for each route
        # =====================================================================
        for idx, route in enumerate(routes):
            host = route.get("host", "")
            path = route.get("path", "/")
            backend = route.get("backend", {})

            service_name = backend.get("serviceName")
            service_namespace = backend.get("serviceNamespace", namespace)
            service_port = backend.get("port")

            # Generate names for this route
            route_suffix = f"r{idx}"
            pool_name = generate_resource_name(name, f"pool-{route_suffix}")
            routing_name = generate_resource_name(name, f"cr-{route_suffix}")

            logger.info(f"Processing route {idx}: {host}{path} -> {service_namespace}/{service_name}:{service_port}")

            # Resolve service to endpoints
            endpoints = resolve_service_endpoints(service_name, service_namespace, service_port)
            logger.info(f"Resolved {len(endpoints)} endpoints for {service_name}")

            # Create server pool
            pool_result = client.create_server_pool(pool_name)
            if pool_result["status_code"] not in [200, 201]:
                existing = client.get_server_pool(pool_name)
                if existing["status_code"] != 200:
                    logger.warning(f"Failed to create server pool {pool_name}: {pool_result}")

            # Add servers to pool
            for ep in endpoints:
                server_result = client.add_server_to_pool(pool_name, ep["ip"], ep["port"])
                logger.info(f"Added server {ep['ip']}:{ep['port']} to pool {pool_name}: {server_result['status_code']}")

            created_pools.append(pool_name)

            # Create content routing policy
            cr_result = client.create_content_routing_policy(routing_name, pool_name)
            if cr_result["status_code"] not in [200, 201]:
                existing = client.get_content_routing_policy(routing_name)
                if existing["status_code"] != 200:
                    logger.warning(f"Failed to create content routing {routing_name}: {cr_result}")

            # Add match condition for host header
            if host:
                escaped_host = host.replace('.', r'\.')
                match_result = client.add_match_condition(
                    routing_policy_name=routing_name,
                    match_type="host-header",
                    match_value=f"^{escaped_host}$",
                )
                logger.info(f"Added host match for {host}: {match_result['status_code']}")

            # Add path match if specified
            if path and path != "/":
                path_result = client.add_match_condition(
                    routing_policy_name=routing_name,
                    match_type="request-url",
                    match_value=f"^{path}",
                )
                logger.info(f"Added path match for {path}: {path_result['status_code']}")

            created_routing_rules.append(routing_name)

        # =====================================================================
        # Step 3: Create Server Policy
        # =====================================================================
        logger.info(f"Creating server policy: {policy_name}")

        policy_result = client.create_policy(
            name=policy_name,
            vserver=vserver_name,
            web_protection_profile=policy_spec.get("webProtectionProfile", "Inline Standard Protection"),
            http_service=policy_spec.get("httpService", "HTTP"),
            https_service=policy_spec.get("httpsService", "HTTPS"),
            syn_cookie=policy_spec.get("synCookie", "enable"),
            http_to_https=policy_spec.get("httpToHttps", "disable"),
        )

        if policy_result["status_code"] not in [200, 201]:
            existing = client.get_policy(policy_name)
            if existing["status_code"] != 200:
                logger.warning(f"Failed to create policy {policy_name}: {policy_result}")

        # =====================================================================
        # Step 4: Wire content routing rules into policy
        # =====================================================================
        logger.info(f"Wiring {len(created_routing_rules)} content routing rules to policy")

        for idx, routing_name in enumerate(created_routing_rules):
            # First rule is default if no specific host match
            is_default = (idx == 0 and not routes[0].get("host"))

            wire_result = client.add_content_routing_to_policy(
                policy_name=policy_name,
                content_routing_name=routing_name,
                is_default=is_default,
            )
            logger.info(f"Wired {routing_name} to policy: {wire_result['status_code']}")

        # =====================================================================
        # Update status
        # =====================================================================
        patch.status["state"] = "Ready"
        patch.status["message"] = "Successfully reconciled"
        patch.status["virtualServer"] = vserver_name
        patch.status["policy"] = policy_name
        patch.status["serverPools"] = created_pools
        patch.status["contentRoutingRules"] = created_routing_rules

        logger.info(f"Successfully reconciled FortiWebIngress {namespace}/{name}")

    except Exception as e:
        logger.exception(f"Failed to reconcile FortiWebIngress {namespace}/{name}")
        patch.status["state"] = "Error"
        patch.status["message"] = str(e)
        raise
    finally:
        client.close()


@kopf.on.delete("fortiweb.40docs.com", "v1", "fortiwebingresses")
async def delete_fortiweb_ingress(spec, name, namespace, status, **kwargs):
    """
    Clean up FortiWeb resources when CR is deleted.

    Deletion order (reverse of creation):
    1. Server Policy
    2. Content Routing Policies
    3. Server Pools
    4. Virtual Server
    """
    logger.info(f"Deleting FortiWebIngress {namespace}/{name}")

    # Get FortiWeb connection config
    fortiweb_spec = spec.get("fortiweb", {})
    try:
        credentials = get_credentials(
            namespace,
            fortiweb_spec.get("credentialsSecret"),
            fortiweb_spec.get("credentialsSecretNamespace"),
        )
    except Exception as e:
        logger.warning(f"Could not get credentials for cleanup: {e}")
        return

    config = FortiWebConfig(
        address=fortiweb_spec.get("address"),
        username=credentials["username"],
        password=credentials["password"],
    )

    client = FortiWebClient(config)

    try:
        vserver_spec = spec.get("virtualServer", {})
        policy_spec = spec.get("policy", {})

        vserver_name = vserver_spec.get("name", name)
        policy_name = policy_spec.get("name", name)

        # Get resource lists from status or regenerate names
        server_pools = status.get("serverPools", [])
        routing_rules = status.get("contentRoutingRules", [])

        # If status doesn't have the lists, regenerate from routes
        if not server_pools:
            routes = spec.get("routes", [])
            for idx in range(len(routes)):
                route_suffix = f"r{idx}"
                server_pools.append(generate_resource_name(name, f"pool-{route_suffix}"))
                routing_rules.append(generate_resource_name(name, f"cr-{route_suffix}"))

        # Delete policy first
        logger.info(f"Deleting policy: {policy_name}")
        client.delete_policy(policy_name)

        # Delete content routing rules
        for routing_name in routing_rules:
            logger.info(f"Deleting content routing: {routing_name}")
            client.delete_content_routing_policy(routing_name)

        # Delete server pools
        for pool_name in server_pools:
            logger.info(f"Deleting server pool: {pool_name}")
            client.delete_server_pool(pool_name)

        # Delete virtual server
        logger.info(f"Deleting virtual server: {vserver_name}")
        client.delete_virtual_server(vserver_name)

        logger.info(f"Successfully deleted FortiWebIngress {namespace}/{name}")

    except Exception as e:
        logger.exception(f"Error during cleanup of FortiWebIngress {namespace}/{name}")
        # Don't raise - allow CR deletion to proceed
    finally:
        client.close()


@kopf.on.startup()
async def startup(**kwargs):
    """Initialize Kubernetes client on startup."""
    try:
        kubernetes.config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes config")
    except kubernetes.config.ConfigException:
        kubernetes.config.load_kube_config()
        logger.info("Loaded kubeconfig")


if __name__ == "__main__":
    # For local development
    kopf.run()
