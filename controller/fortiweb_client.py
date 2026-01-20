"""
FortiWeb API Client

Handles all communication with FortiWeb REST API.
Based on observed API calls from the official FortiWeb Ingress Controller.
"""

import base64
import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class FortiWebConfig:
    """FortiWeb connection configuration."""
    address: str  # ip:port
    username: str
    password: str
    verify_ssl: bool = False
    vdom: str = "root"

    @property
    def base_url(self) -> str:
        return f"https://{self.address}/api/v2.0"

    @property
    def auth_token(self) -> str:
        """Generate base64 encoded auth token."""
        auth_data = {
            "username": self.username,
            "password": self.password,
            "vdom": self.vdom
        }
        return base64.b64encode(json.dumps(auth_data).encode()).decode()


class FortiWebClient:
    """Client for FortiWeb REST API."""

    def __init__(self, config: FortiWebConfig):
        self.config = config
        self._client: Optional[httpx.Client] = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.config.base_url,
                headers={
                    "Authorization": self.config.auth_token,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                verify=self.config.verify_ssl,
                timeout=30.0,
            )
        return self._client

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict:
        """Make API request and return response."""
        try:
            response = self.client.request(
                method=method,
                url=endpoint,
                json={"data": data} if data else None,
                params=params,
            )
            result = response.json() if response.text else {}

            if response.status_code >= 400:
                error = result.get("results", {})
                logger.error(
                    f"FortiWeb API error: {method} {endpoint} -> "
                    f"{error.get('errcode')}: {error.get('message')}"
                )

            return {
                "status_code": response.status_code,
                "results": result.get("results", result),
            }
        except Exception as e:
            logger.exception(f"FortiWeb API request failed: {method} {endpoint}")
            return {"status_code": 500, "results": {"error": str(e)}}

    # =========================================================================
    # Virtual Server Management
    # =========================================================================

    def create_virtual_server(self, name: str) -> dict:
        """Create a virtual server."""
        return self._request(
            "POST",
            "/cmdb/server-policy/vserver",
            data={"name": name},
        )

    def get_virtual_server(self, name: str) -> dict:
        """Get virtual server details."""
        return self._request("GET", f"/cmdb/server-policy/vserver?mkey={name}")

    def delete_virtual_server(self, name: str) -> dict:
        """Delete a virtual server."""
        return self._request("DELETE", f"/cmdb/server-policy/vserver?mkey={name}")

    def add_vip_to_vserver(
        self,
        vserver_name: str,
        interface: str,
        use_interface_ip: bool = True,
        vip: str = "",
    ) -> dict:
        """Add VIP configuration to virtual server."""
        data = {
            "interface": interface,
            "status": "enable",
            "use-interface-ip": "enable" if use_interface_ip else "disable",
        }
        # Only include vip field when not using interface IP
        if not use_interface_ip and vip:
            data["vip"] = vip
        return self._request(
            "POST",
            f"/cmdb/server-policy/vserver/vip-list?mkey={vserver_name}",
            data=data,
        )

    # =========================================================================
    # VIP Management
    # =========================================================================

    def create_vip(self, name: str, ip: str, interface: str) -> dict:
        """Create a VIP."""
        return self._request(
            "POST",
            "/cmdb/system/vip",
            data={
                "name": name,
                "vip": ip,
                "vip6": "::/0",
                "interface": interface,
            },
        )

    def delete_vip(self, name: str) -> dict:
        """Delete a VIP."""
        return self._request("DELETE", f"/cmdb/system/vip?mkey={name}")

    # =========================================================================
    # Server Pool Management
    # =========================================================================

    def create_server_pool(
        self,
        name: str,
        health_check: str = "HLTHCK_HTTP",
        lb_algo: str = "round-robin",
    ) -> dict:
        """Create a server pool."""
        return self._request(
            "POST",
            "/cmdb/server-policy/server-pool",
            data={
                "name": name,
                "health": health_check,
                "lb-algo": lb_algo,
                "server-balance": "enable",
                "type": "reverse-proxy",
            },
        )

    def get_server_pool(self, name: str) -> dict:
        """Get server pool details."""
        return self._request("GET", f"/cmdb/server-policy/server-pool?mkey={name}")

    def delete_server_pool(self, name: str) -> dict:
        """Delete a server pool."""
        return self._request("DELETE", f"/cmdb/server-policy/server-pool?mkey={name}")

    def add_server_to_pool(
        self,
        pool_name: str,
        server_ip: str,
        server_port: int,
    ) -> dict:
        """Add a real server to a pool."""
        return self._request(
            "POST",
            f"/cmdb/server-policy/server-pool/pserver-list?mkey={pool_name}",
            data={
                "ip": server_ip,
                "port": str(server_port),
                "status": "enable",
                "server-type": "physical",
                "health-check-inherit": "enable",
                "backup-server": "disable",
                "ssl": "disable",
                "weight": "1",
            },
        )

    def get_server_pool_members(self, pool_name: str) -> dict:
        """Get all members in a server pool."""
        return self._request(
            "GET",
            f"/cmdb/server-policy/server-pool/pserver-list?mkey={pool_name}",
        )

    def delete_server_from_pool(self, pool_name: str, member_id: str) -> dict:
        """Delete a specific server from a pool."""
        return self._request(
            "DELETE",
            f"/cmdb/server-policy/server-pool/pserver-list?mkey={pool_name}&sub_mkey={member_id}",
        )

    # =========================================================================
    # Content Routing Management
    # =========================================================================

    def create_content_routing_policy(
        self,
        name: str,
        server_pool: str,
    ) -> dict:
        """Create an HTTP content routing policy."""
        return self._request(
            "POST",
            "/cmdb/server-policy/http-content-routing-policy",
            data={
                "name": name,
                "server-pool": server_pool,
            },
        )

    def get_content_routing_policy(self, name: str) -> dict:
        """Get content routing policy details."""
        return self._request(
            "GET",
            f"/cmdb/server-policy/http-content-routing-policy?mkey={name}",
        )

    def delete_content_routing_policy(self, name: str) -> dict:
        """Delete a content routing policy."""
        return self._request(
            "DELETE",
            f"/cmdb/server-policy/http-content-routing-policy?mkey={name}",
        )

    def add_match_condition(
        self,
        routing_policy_name: str,
        match_type: str = "http-host",
        match_value: str = "",
    ) -> dict:
        """Add a match condition to content routing policy."""
        return self._request(
            "POST",
            f"/cmdb/server-policy/http-content-routing-policy/content-routing-match-list?mkey={routing_policy_name}",
            data={
                "match-object": match_type,
                "match-condition": "match-reg",
                "match-expression": match_value,
            },
        )

    # =========================================================================
    # Server Policy Management
    # =========================================================================

    def create_policy(
        self,
        name: str,
        vserver: str,
        web_protection_profile: str = "Inline Standard Protection",
        http_service: str = "HTTP",
        https_service: str = "HTTPS",
        deployment_mode: str = "http-content-routing",
        certificate: str = "",
        syn_cookie: str = "enable",
        http_to_https: str = "disable",
    ) -> dict:
        """Create a server policy."""
        data = {
            "name": name,
            "vserver": vserver,
            "web-protection-profile": web_protection_profile,
            "service": http_service,
            "https-service": https_service,
            "deployment-mode": deployment_mode,
            "syncookie": syn_cookie,
            "http-to-https": http_to_https,
            "protocol": "HTTP",
            "ssl": "enable" if certificate else "disable",
        }
        if certificate:
            data["certificate"] = certificate

        return self._request("POST", "/cmdb/server-policy/policy", data=data)

    def get_policy(self, name: str) -> dict:
        """Get policy details."""
        return self._request("GET", f"/cmdb/server-policy/policy?mkey={name}")

    def delete_policy(self, name: str) -> dict:
        """Delete a policy."""
        return self._request("DELETE", f"/cmdb/server-policy/policy?mkey={name}")

    def add_content_routing_to_policy(
        self,
        policy_name: str,
        content_routing_name: str,
        is_default: bool = False,
    ) -> dict:
        """Add a content routing rule to a policy."""
        return self._request(
            "POST",
            f"/cmdb/server-policy/policy/http-content-routing-list?mkey={policy_name}",
            data={
                "content-routing-policy-name": content_routing_name,
                "is-default": "yes" if is_default else "no",
                "profile-inherit": "enable",
                "status": "enable",
            },
        )

    def get_policy_content_routing_list(self, policy_name: str) -> dict:
        """Get content routing rules attached to a policy."""
        return self._request(
            "GET",
            f"/cmdb/server-policy/policy/http-content-routing-list?mkey={policy_name}",
        )

    # =========================================================================
    # Certificate Management
    # =========================================================================

    def upload_local_certificate(
        self,
        name: str,
        cert_pem: str,
        key_pem: str,
    ) -> dict:
        """
        Upload a local certificate to FortiWeb.

        Uses the import_certificate endpoint with multipart form data.
        The certificate name is derived from the filename (without extension).

        Args:
            name: Certificate name in FortiWeb (used as filename prefix)
            cert_pem: PEM-encoded certificate (can include chain)
            key_pem: PEM-encoded private key
        """
        try:
            # Use httpx directly (not self.client) to avoid default Content-Type header
            # The client has Content-Type: application/json which breaks multipart uploads
            response = httpx.post(
                f"{self.config.base_url}/system/certificate.local.import_certificate",
                headers={
                    "Authorization": self.config.auth_token,
                    "Accept": "application/json, text/plain, */*",
                },
                files={
                    "certificateFile": (f"{name}.crt", cert_pem.encode(), "application/x-pem-file"),
                    "keyFile": (f"{name}.key", key_pem.encode(), "application/x-pem-file"),
                },
                data={
                    "type": "certificate",
                    "hsm": "undefined",
                    "password": "undefined",
                },
                verify=self.config.verify_ssl,
                timeout=30.0,
            )
            result = response.json() if response.text else {}
            if response.status_code >= 400:
                logger.error(
                    f"FortiWeb API error: POST /system/certificate.local.import_certificate -> "
                    f"{result.get('errcode')}: {result.get('message')}"
                )
            return {
                "status_code": response.status_code,
                "results": result,
            }
        except Exception as e:
            logger.exception("FortiWeb certificate upload failed")
            return {"status_code": 500, "results": {"error": str(e)}}

    def get_local_certificate(self, name: str) -> dict:
        """Get local certificate details."""
        return self._request("GET", f"/cmdb/system/certificate.local?mkey={name}")

    def delete_local_certificate(self, name: str) -> dict:
        """Delete a local certificate."""
        return self._request("DELETE", f"/cmdb/system/certificate.local?mkey={name}")

    def create_sni_policy(self, name: str) -> dict:
        """Create an SNI policy for multi-certificate support."""
        return self._request(
            "POST",
            "/cmdb/system/certificate.sni",
            data={"name": name},
        )

    def get_sni_policy(self, name: str) -> dict:
        """Get SNI policy details."""
        return self._request("GET", f"/cmdb/system/certificate.sni?mkey={name}")

    def delete_sni_policy(self, name: str) -> dict:
        """Delete an SNI policy."""
        return self._request("DELETE", f"/cmdb/system/certificate.sni?mkey={name}")

    def add_sni_member(
        self,
        sni_policy_name: str,
        domain: str,
        certificate: str,
    ) -> dict:
        """
        Add an SNI member (domain-to-certificate mapping) to an SNI policy.

        Args:
            sni_policy_name: Name of the SNI policy
            domain: Domain/hostname pattern (e.g., "app.example.com")
            certificate: Name of the local certificate to use
        """
        return self._request(
            "POST",
            f"/cmdb/system/certificate.sni/members?mkey={sni_policy_name}",
            data={
                "domain-type": "plain",
                "domain": domain,
                "local-cert": certificate,
            },
        )

    def delete_sni_member(self, sni_policy_name: str, member_id: str) -> dict:
        """Delete an SNI member from a policy."""
        return self._request(
            "DELETE",
            f"/cmdb/system/certificate.sni/members?mkey={sni_policy_name}&sub_mkey={member_id}",
        )

    def update_policy_sni(self, policy_name: str, sni_policy: str) -> dict:
        """
        Update a server policy to use SNI for certificate selection.

        Args:
            policy_name: Name of the server policy
            sni_policy: Name of the SNI policy
        """
        return self._request(
            "PUT",
            f"/cmdb/server-policy/policy?mkey={policy_name}",
            data={
                "ssl": "enable",
                "sni": "enable",
                "sni-certificate": sni_policy,
            },
        )

    # =========================================================================
    # Session Management
    # =========================================================================

    def logout(self) -> dict:
        """Logout from FortiWeb."""
        return self._request("GET", "/logout")
