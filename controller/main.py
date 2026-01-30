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


def get_fortiweb_config_defaults(namespace: str) -> dict:
    """
    Read FortiWeb network config from the fortiweb-config secret.

    This secret is synced from AWS Secrets Manager via External Secrets
    and contains the FortiWeb IPs that would otherwise need to be hardcoded.

    Returns dict with keys:
        - address: FortiWeb API address (ip:port)
        - public_ip: FortiWeb public EIP (for DNS target)
        - port1_ip: FortiWeb port1 private IP (for virtual server)
    """
    api = kubernetes.client.CoreV1Api()
    defaults = {
        "address": None,
        "public_ip": None,
        "port1_ip": None,
    }

    try:
        secret = api.read_namespaced_secret("fortiweb-config", namespace)
        data = secret.data or {}

        # Build address from IP and port
        fw_ip = base64.b64decode(data.get("FORTIWEB_IP", "")).decode() if data.get("FORTIWEB_IP") else ""
        fw_port = base64.b64decode(data.get("FORTIWEB_PORT", "")).decode() if data.get("FORTIWEB_PORT") else "8443"
        if fw_ip:
            defaults["address"] = f"{fw_ip}:{fw_port}"

        # Public IP for DNS
        if data.get("FORTIWEB_PUBLIC_IP"):
            defaults["public_ip"] = base64.b64decode(data["FORTIWEB_PUBLIC_IP"]).decode()

        # Port1 IP for virtual server
        if data.get("FORTIWEB_PORT1_IP"):
            defaults["port1_ip"] = base64.b64decode(data["FORTIWEB_PORT1_IP"]).decode()

        logger.info(f"Loaded FortiWeb config defaults: address={defaults['address']}, public_ip={defaults['public_ip']}")

    except kubernetes.client.ApiException as e:
        if e.status == 404:
            logger.info("No fortiweb-config secret found, using CR values only")
        else:
            logger.warning(f"Failed to read fortiweb-config secret: {e}")

    return defaults


def get_tls_certificate(namespace: str, secret_name: str, secret_namespace: Optional[str] = None) -> dict:
    """
    Read TLS certificate and key from a Kubernetes TLS secret.

    Args:
        namespace: Default namespace if secret_namespace not specified
        secret_name: Name of the TLS secret
        secret_namespace: Namespace of the TLS secret (optional)

    Returns:
        dict with 'cert' and 'key' as PEM strings, or None values if not found
    """
    api = kubernetes.client.CoreV1Api()
    ns = secret_namespace or namespace

    try:
        secret = api.read_namespaced_secret(secret_name, ns)

        if secret.type != "kubernetes.io/tls":
            logger.warning(f"Secret {ns}/{secret_name} is not a TLS secret (type: {secret.type})")
            return {"cert": None, "key": None}

        cert_pem = base64.b64decode(secret.data.get("tls.crt", "")).decode()
        key_pem = base64.b64decode(secret.data.get("tls.key", "")).decode()

        return {"cert": cert_pem, "key": key_pem}

    except kubernetes.client.ApiException as e:
        if e.status == 404:
            logger.info(f"TLS secret {ns}/{secret_name} not found (may not be issued yet)")
            return {"cert": None, "key": None}
        raise kopf.TemporaryError(f"Failed to read TLS secret {ns}/{secret_name}: {e}")


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

        # Find the target port from service spec (service port -> target port mapping)
        target_port = port
        port_name = None
        for svc_port in service.spec.ports or []:
            if svc_port.port == port:
                # Get the target port (could be int or string name)
                if isinstance(svc_port.target_port, int):
                    target_port = svc_port.target_port
                elif svc_port.target_port:
                    # It's a named port, we'll resolve from endpoints
                    port_name = str(svc_port.target_port)
                else:
                    target_port = svc_port.port
                break

        logger.info(f"Service port {port} maps to target port {target_port} (name: {port_name})")

        # For ClusterIP/NodePort services, get endpoints
        endpoints = api.read_namespaced_endpoints(service_name, service_namespace)

        result = []
        for subset in endpoints.subsets or []:
            # If we have a named port, resolve it from endpoints
            resolved_port = target_port
            if port_name:
                for ep_port in subset.ports or []:
                    if ep_port.name == port_name:
                        resolved_port = ep_port.port
                        break

            for address in subset.addresses or []:
                result.append({
                    "ip": address.ip,
                    "port": resolved_port,
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


def create_dns_endpoint(name: str, namespace: str, hostnames: list[str], target_ip: str, owner_ref: dict) -> None:
    """
    Create or update a DNSEndpoint resource for external-dns.

    Args:
        name: Name for the DNSEndpoint resource
        namespace: Namespace to create the DNSEndpoint in
        hostnames: List of hostnames to create A records for
        target_ip: IP address to point the A records to
        owner_ref: Owner reference for garbage collection
    """
    api = kubernetes.client.CustomObjectsApi()

    endpoints = [
        {
            "dnsName": hostname,
            "recordType": "A",
            "targets": [target_ip],
            "recordTTL": 300,
        }
        for hostname in hostnames
    ]

    dns_endpoint = {
        "apiVersion": "externaldns.k8s.io/v1alpha1",
        "kind": "DNSEndpoint",
        "metadata": {
            "name": f"{name}-dns",
            "namespace": namespace,
            "ownerReferences": [owner_ref],
        },
        "spec": {
            "endpoints": endpoints,
        },
    }

    try:
        # Try to get existing
        api.get_namespaced_custom_object(
            group="externaldns.k8s.io",
            version="v1alpha1",
            namespace=namespace,
            plural="dnsendpoints",
            name=f"{name}-dns",
        )
        # Update if exists
        api.patch_namespaced_custom_object(
            group="externaldns.k8s.io",
            version="v1alpha1",
            namespace=namespace,
            plural="dnsendpoints",
            name=f"{name}-dns",
            body=dns_endpoint,
        )
        logger.info(f"Updated DNSEndpoint {name}-dns with {len(hostnames)} hostnames")
    except kubernetes.client.ApiException as e:
        if e.status == 404:
            # Create if doesn't exist
            api.create_namespaced_custom_object(
                group="externaldns.k8s.io",
                version="v1alpha1",
                namespace=namespace,
                plural="dnsendpoints",
                body=dns_endpoint,
            )
            logger.info(f"Created DNSEndpoint {name}-dns with {len(hostnames)} hostnames")
        else:
            raise


def delete_dns_endpoint(name: str, namespace: str) -> None:
    """Delete DNSEndpoint resource if it exists."""
    api = kubernetes.client.CustomObjectsApi()

    try:
        api.delete_namespaced_custom_object(
            group="externaldns.k8s.io",
            version="v1alpha1",
            namespace=namespace,
            plural="dnsendpoints",
            name=f"{name}-dns",
        )
        logger.info(f"Deleted DNSEndpoint {name}-dns")
    except kubernetes.client.ApiException as e:
        if e.status != 404:
            logger.warning(f"Failed to delete DNSEndpoint {name}-dns: {e}")


@kopf.on.create("fortiwebingress.io", "v1", "fortiwebingresses")
@kopf.on.update("fortiwebingress.io", "v1", "fortiwebingresses")
async def reconcile_fortiweb_ingress(spec, name, namespace, status, patch, meta, **kwargs):
    """
    Reconcile FortiWebIngress resource.

    Creates/updates:
    1. Virtual Server
    2. Server Pools (one per route)
    3. Content Routing Policies (one per route)
    4. Server Policy with all content routing rules wired in
    5. DNSEndpoint for external-dns (if dns.enabled)
    """
    logger.info(f"Reconciling FortiWebIngress {namespace}/{name}")

    # Update status to syncing
    patch.status["state"] = "Syncing"
    patch.status["message"] = "Starting reconciliation"

    # Load defaults from fortiweb-config secret (synced from AWS Secrets Manager)
    config_defaults = get_fortiweb_config_defaults(namespace)

    # Get FortiWeb connection config
    fortiweb_spec = spec.get("fortiweb", {})
    credentials = get_credentials(
        namespace,
        fortiweb_spec.get("credentialsSecret"),
        fortiweb_spec.get("credentialsSecretNamespace"),
    )

    # Use CR value if specified, otherwise fall back to secret defaults
    fortiweb_address = fortiweb_spec.get("address") or config_defaults.get("address")
    if not fortiweb_address:
        raise kopf.PermanentError("FortiWeb address not specified in CR or fortiweb-config secret")

    config = FortiWebConfig(
        address=fortiweb_address,
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

        # Add VIP to virtual server (use default from secret if not specified)
        vip_address = vserver_spec.get("ip") or config_defaults.get("port1_ip") or ""
        vip_result = client.add_vip_to_vserver(
            vserver_name=vserver_name,
            interface=vserver_spec.get("interface", "port1"),
            use_interface_ip=vserver_spec.get("useInterfaceIP", True),
            vip=vip_address,
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

            # Create custom health check if specified in route config
            health_check_name = "HLTHCK_HTTP"  # Default FortiWeb health check
            health_check_config = route.get("healthCheck")
            if health_check_config:
                hc_name = generate_resource_name(name, f"hc-{route_suffix}")
                hc_result = client.create_health_check(
                    name=hc_name,
                    url_path=health_check_config.get("path", "/"),
                    method=health_check_config.get("method", "head"),
                    response_code=int(health_check_config.get("responseCode", 200)),
                )
                if hc_result["status_code"] in [200, 201]:
                    health_check_name = hc_name
                    logger.info(f"Created custom health check {hc_name} with path {health_check_config.get('path')}")
                elif hc_result["status_code"] == 500:
                    # Might already exist
                    existing = client.get_health_check(hc_name)
                    if existing["status_code"] == 200:
                        health_check_name = hc_name
                        logger.info(f"Health check {hc_name} already exists")
                    else:
                        logger.warning(f"Failed to create health check {hc_name}: {hc_result}")
                else:
                    logger.warning(f"Failed to create health check {hc_name}: {hc_result}")

            # Create server pool with health check
            pool_result = client.create_server_pool(pool_name, health_check=health_check_name)
            if pool_result["status_code"] not in [200, 201]:
                existing = client.get_server_pool(pool_name)
                if existing["status_code"] != 200:
                    logger.warning(f"Failed to create server pool {pool_name}: {pool_result}")

            # Reconcile pool members (add new, remove stale)
            current_members_resp = client.get_server_pool_members(pool_name)
            actual_members = {}  # {ip:port -> member_id}
            if current_members_resp.get("results") and isinstance(current_members_resp["results"], list):
                for member in current_members_resp["results"]:
                    key = f"{member.get('ip')}:{member.get('port')}"
                    # Member ID is typically the IP address in FortiWeb
                    actual_members[key] = member.get("id") or member.get("_id") or member.get("ip")

            # Build desired state from K8s endpoints
            desired_members = {f"{ep['ip']}:{ep['port']}" for ep in endpoints}

            # Remove stale members (in actual but not in desired)
            for member_key, member_id in actual_members.items():
                if member_key not in desired_members:
                    logger.info(f"Removing stale member {member_key} from pool {pool_name}")
                    delete_result = client.delete_server_from_pool(pool_name, member_id)
                    if delete_result["status_code"] not in [200, 204]:
                        logger.warning(f"Failed to remove stale member {member_key}: {delete_result}")

            # Add new members (in desired but not in actual)
            for ep in endpoints:
                member_key = f"{ep['ip']}:{ep['port']}"
                if member_key not in actual_members:
                    logger.info(f"Adding member {member_key} to pool {pool_name}")
                    server_result = client.add_server_to_pool(pool_name, ep["ip"], ep["port"])
                    if server_result["status_code"] not in [200, 201]:
                        logger.warning(f"Failed to add member {member_key}: {server_result}")

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
                    match_type="http-host",
                    match_value=f"^{escaped_host}$",
                )
                logger.info(f"Added host match for {host}: {match_result['status_code']}")

            # Add path match if specified
            if path and path != "/":
                path_result = client.add_match_condition(
                    routing_policy_name=routing_name,
                    match_type="http-request",
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

        # Get existing content routing rules to check for updates
        existing_cr_list = client.get_policy_content_routing_list(policy_name)
        existing_cr_map = {}
        if existing_cr_list.get("status_code") == 200:
            for item in existing_cr_list.get("results", []):
                cr_name = item.get("content-routing-policy-name", "")
                cr_id = item.get("id", "")
                if cr_name and cr_id:
                    existing_cr_map[cr_name] = cr_id

        for idx, routing_name in enumerate(created_routing_rules):
            # Route with path "/" is the catch-all default (evaluated last)
            route_path = routes[idx].get("path", "/")
            is_default = (route_path == "/")

            if routing_name in existing_cr_map:
                # Update existing rule to ensure is_default is set correctly
                cr_id = existing_cr_map[routing_name]
                wire_result = client.update_content_routing_in_policy(
                    policy_name=policy_name,
                    content_routing_id=cr_id,
                    content_routing_name=routing_name,
                    is_default=is_default,
                )
                logger.info(f"Updated {routing_name} (id={cr_id}, is_default={is_default}): {wire_result['status_code']}")
            else:
                # Add new rule
                wire_result = client.add_content_routing_to_policy(
                    policy_name=policy_name,
                    content_routing_name=routing_name,
                    is_default=is_default,
                )
                logger.info(f"Added {routing_name} (is_default={is_default}): {wire_result['status_code']}")

        # =====================================================================
        # Step 5: Configure TLS/HTTPS with per-host certificates
        # =====================================================================
        tls_routes = [r for r in routes if r.get("tls", {}).get("enabled")]

        if tls_routes:
            logger.info(f"Configuring TLS for {len(tls_routes)} routes")
            sni_policy_name = f"{name}-sni"
            uploaded_certs = []

            # Create SNI policy for multi-certificate support
            sni_result = client.create_sni_policy(sni_policy_name)
            if sni_result["status_code"] not in [200, 201, 500]:  # 500 might mean exists
                existing = client.get_sni_policy(sni_policy_name)
                if existing["status_code"] != 200:
                    logger.warning(f"Failed to create SNI policy: {sni_result}")

            # Process each TLS-enabled route
            for route in tls_routes:
                host = route.get("host")
                tls_config = route.get("tls", {})
                secret_name = tls_config.get("secretName")
                secret_ns = tls_config.get("secretNamespace", namespace)

                if not secret_name:
                    logger.warning(f"TLS enabled for {host} but no secretName specified")
                    continue

                # Read TLS certificate from Kubernetes secret
                tls_data = get_tls_certificate(namespace, secret_name, secret_ns)

                if not tls_data["cert"] or not tls_data["key"]:
                    logger.warning(f"TLS secret {secret_ns}/{secret_name} not ready for {host}")
                    continue

                # Generate certificate name for FortiWeb (sanitize hostname)
                cert_name = host.replace(".", "-").replace("*", "wildcard")

                # Upload certificate to FortiWeb
                upload_result = client.upload_local_certificate(
                    name=cert_name,
                    cert_pem=tls_data["cert"],
                    key_pem=tls_data["key"],
                )

                if upload_result["status_code"] in [200, 201]:
                    logger.info(f"Uploaded certificate {cert_name} for {host}")
                    uploaded_certs.append(cert_name)
                elif upload_result["status_code"] == 500:
                    # Might already exist, check and continue
                    existing = client.get_local_certificate(cert_name)
                    if existing["status_code"] == 200:
                        logger.info(f"Certificate {cert_name} already exists")
                        uploaded_certs.append(cert_name)
                    else:
                        logger.warning(f"Failed to upload certificate for {host}: {upload_result}")
                        continue
                else:
                    logger.warning(f"Failed to upload certificate for {host}: {upload_result}")
                    continue

                # Add SNI member to map hostname to certificate
                sni_member_result = client.add_sni_member(
                    sni_policy_name=sni_policy_name,
                    domain=host,
                    certificate=cert_name,
                )
                if sni_member_result["status_code"] in [200, 201, 500]:
                    logger.info(f"Added SNI mapping: {host} -> {cert_name}")
                else:
                    logger.warning(f"Failed to add SNI member for {host}: {sni_member_result}")

            # Update policy to use SNI for certificate selection
            if uploaded_certs:
                sni_update = client.update_policy_sni(policy_name, sni_policy_name)
                if sni_update["status_code"] in [200, 201]:
                    logger.info(f"Enabled SNI on policy {policy_name}")
                    patch.status["sniPolicy"] = sni_policy_name
                    patch.status["certificates"] = uploaded_certs
                else:
                    logger.warning(f"Failed to enable SNI on policy: {sni_update}")

        # =====================================================================
        # Step 6: Create DNSEndpoint for external-dns (if enabled)
        # =====================================================================
        dns_spec = spec.get("dns", {})
        dns_enabled = dns_spec.get("enabled", False)
        # Use CR value if specified, otherwise fall back to public IP from secret
        dns_target = dns_spec.get("target") or config_defaults.get("public_ip") or ""

        if dns_enabled and dns_target:
            # Collect all hostnames from routes
            hostnames = [route.get("host") for route in routes if route.get("host")]

            if hostnames:
                # Create owner reference for garbage collection
                owner_ref = {
                    "apiVersion": "fortiwebingress.io/v1",
                    "kind": "FortiWebIngress",
                    "name": name,
                    "uid": meta.get("uid"),
                    "controller": True,
                    "blockOwnerDeletion": True,
                }

                create_dns_endpoint(
                    name=name,
                    namespace=namespace,
                    hostnames=hostnames,
                    target_ip=dns_target,
                    owner_ref=owner_ref,
                )
                patch.status["dnsEndpoint"] = f"{name}-dns"
                patch.status["dnsHostnames"] = hostnames
                logger.info(f"Created DNSEndpoint with target {dns_target}")
            else:
                logger.warning("DNS enabled but no hostnames found in routes")
        elif dns_enabled and not dns_target:
            logger.warning("DNS enabled but no target IP specified in CR or fortiweb-config secret")

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


@kopf.on.delete("fortiwebingress.io", "v1", "fortiwebingresses")
async def delete_fortiweb_ingress(spec, name, namespace, status, **kwargs):
    """
    Clean up FortiWeb resources when CR is deleted.

    Deletion order (reverse of creation):
    1. DNSEndpoint (deleted via owner reference, but explicit delete for safety)
    2. Server Policy
    3. Content Routing Policies
    4. Server Pools
    5. Virtual Server
    """
    logger.info(f"Deleting FortiWebIngress {namespace}/{name}")

    # Delete DNSEndpoint first (also handled by owner reference garbage collection)
    delete_dns_endpoint(name, namespace)

    # Load defaults from fortiweb-config secret
    config_defaults = get_fortiweb_config_defaults(namespace)

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

    # Use CR value if specified, otherwise fall back to secret defaults
    fortiweb_address = fortiweb_spec.get("address") or config_defaults.get("address")
    if not fortiweb_address:
        logger.warning("FortiWeb address not available, skipping FortiWeb cleanup")
        return

    config = FortiWebConfig(
        address=fortiweb_address,
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

        # Delete custom health checks (named like <name>-hc-r0, <name>-hc-r1, etc.)
        routes = spec.get("routes", [])
        for idx, route in enumerate(routes):
            if route.get("healthCheck"):
                hc_name = generate_resource_name(name, f"hc-r{idx}")
                logger.info(f"Deleting health check: {hc_name}")
                client.delete_health_check(hc_name)

        # Delete virtual server
        logger.info(f"Deleting virtual server: {vserver_name}")
        client.delete_virtual_server(vserver_name)

        logger.info(f"Successfully deleted FortiWebIngress {namespace}/{name}")

    except Exception as e:
        logger.exception(f"Error during cleanup of FortiWebIngress {namespace}/{name}")
        # Don't raise - allow CR deletion to proceed
    finally:
        client.close()


@kopf.on.event("", "v1", "secrets")
async def on_secret_change(event, name, namespace, body, **kwargs):
    """
    Watch TLS secrets and trigger FortiWebIngress reconciliation when they change.

    This handles the race condition where FortiWebIngress is created before
    cert-manager has issued the TLS certificates.
    """
    # Only care about TLS secrets
    if body.get("type") != "kubernetes.io/tls":
        return

    # Only care about create/update events (not delete)
    event_type = event.get("type")
    if event_type not in ("ADDED", "MODIFIED"):
        return

    logger.info(f"TLS secret {namespace}/{name} changed, checking for FortiWebIngress references")

    # Find FortiWebIngress resources that reference this secret
    api = kubernetes.client.CustomObjectsApi()
    try:
        # List all FortiWebIngress resources
        fwi_list = api.list_cluster_custom_object(
            group="fortiwebingress.io",
            version="v1",
            plural="fortiwebingresses",
        )

        for fwi in fwi_list.get("items", []):
            fwi_name = fwi["metadata"]["name"]
            fwi_namespace = fwi["metadata"]["namespace"]
            routes = fwi.get("spec", {}).get("routes", [])

            # Check if any route references this TLS secret
            for route in routes:
                tls_config = route.get("tls", {})
                if not tls_config.get("enabled"):
                    continue

                secret_name = tls_config.get("secretName")
                # Secret namespace defaults to FortiWebIngress namespace
                secret_ns = tls_config.get("secretNamespace", fwi_namespace)

                if secret_name == name and secret_ns == namespace:
                    logger.info(
                        f"TLS secret {namespace}/{name} is referenced by "
                        f"FortiWebIngress {fwi_namespace}/{fwi_name}, triggering reconciliation"
                    )

                    # Touch the FortiWebIngress to trigger reconciliation
                    import time
                    api.patch_namespaced_custom_object(
                        group="fortiwebingress.io",
                        version="v1",
                        plural="fortiwebingresses",
                        namespace=fwi_namespace,
                        name=fwi_name,
                        body={
                            "metadata": {
                                "annotations": {
                                    "fortiwebingress.io/tls-secret-updated": str(int(time.time()))
                                }
                            }
                        },
                    )
                    break  # Only need to trigger once per FortiWebIngress

    except kubernetes.client.ApiException as e:
        logger.warning(f"Failed to list/patch FortiWebIngress resources: {e}")


@kopf.on.event("", "v1", "endpoints")
async def on_endpoints_change(event, name, namespace, body, **kwargs):
    """
    Watch Endpoints and trigger FortiWebIngress reconciliation when
    backend service endpoints change (pod IP additions/removals).

    This ensures FortiWeb server pools stay in sync when pods roll
    (e.g., new image deployments, scaling events, node migrations).
    """
    # Only care about meaningful changes (not deletions of services we don't track)
    event_type = event.get("type")
    if event_type not in ("ADDED", "MODIFIED"):
        return

    # Extract current ready addresses for comparison
    subsets = body.get("subsets") or []
    current_ips = set()
    for subset in subsets:
        for address in subset.get("addresses") or []:
            current_ips.add(address.get("ip"))

    # Find FortiWebIngress resources that reference this service
    api = kubernetes.client.CustomObjectsApi()
    try:
        fwi_list = api.list_cluster_custom_object(
            group="fortiwebingress.io",
            version="v1",
            plural="fortiwebingresses",
        )

        for fwi in fwi_list.get("items", []):
            fwi_name = fwi["metadata"]["name"]
            fwi_namespace = fwi["metadata"]["namespace"]
            routes = fwi.get("spec", {}).get("routes", [])

            for route in routes:
                backend = route.get("backend", {})
                service_name = backend.get("serviceName")
                service_namespace = backend.get("serviceNamespace", fwi_namespace)

                if service_name == name and service_namespace == namespace:
                    logger.info(
                        f"Endpoints {namespace}/{name} changed (IPs: {current_ips}), "
                        f"triggering reconciliation for FortiWebIngress {fwi_namespace}/{fwi_name}"
                    )

                    import time
                    api.patch_namespaced_custom_object(
                        group="fortiwebingress.io",
                        version="v1",
                        plural="fortiwebingresses",
                        namespace=fwi_namespace,
                        name=fwi_name,
                        body={
                            "metadata": {
                                "annotations": {
                                    "fortiwebingress.io/endpoints-updated": str(int(time.time()))
                                }
                            }
                        },
                    )
                    break  # Only need to trigger once per FortiWebIngress

    except kubernetes.client.ApiException as e:
        logger.warning(f"Failed to list/patch FortiWebIngress for endpoints change: {e}")


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
