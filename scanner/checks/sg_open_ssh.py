from scanner.registry import BaseCheck, CheckResult, CheckStatus
from scanner.models import Finding
from scanner.scoring import CAPABILITY_TO_SEVERITY, PORT_TO_CAPABILITY

ADMIN_PORTS = (22, 3389)
ANYWHERE_CIDR = "0.0.0.0/0"

def _open_admin_ports(rule):
    open_cidr = False
    ip_protocol = rule["IpProtocol"]

    for cidr_entry in rule["IpRanges"]:
         if cidr_entry["CidrIp"] == ANYWHERE_CIDR:
            open_cidr = True
            break

    if not open_cidr:
        return []

    if ip_protocol != "tcp" and ip_protocol != "-1":
        return []

    if ip_protocol == "-1":
        return list(ADMIN_PORTS)

    admin_port_list = []

    for port in ADMIN_PORTS:
        if rule["FromPort"] <= port <= rule["ToPort"]:
            admin_port_list.append(port)

    return admin_port_list

class SecurityGroupAdminPorts(BaseCheck):
    control_id = "6.3"
    title = "Security group allows 0.0.0.0/0 on port 22 and 3389"
    remediable = True
    requires =  ["security_groups"]

    def evaluate(self, snapshot):
        if snapshot["security_groups"]["status"] != "ok":
            return CheckResult(
                status=CheckStatus.CANT_EVALUATE,
                findings=[],
                control_id=self.control_id,
                error=snapshot["security_groups"]["status"],
                unevaluated=[],
            )
        security_groups = snapshot["security_groups"]["document"]
        findings_list = []
        account_id = snapshot["account_id"]
        unevaluated_list = []
        for group in security_groups:
            ports = set()
            for permission in group["IpPermissions"]:
                ports.update(_open_admin_ports(permission))

            for port in ports:
                findings_list.append(Finding(
                    control_id=self.control_id,
                    title=self.title,
                    severity=CAPABILITY_TO_SEVERITY[PORT_TO_CAPABILITY.get(port, 3)],
                    resource_id=group["GroupId"],
                    resource_sub_id=str(port),
                    region=group["region"],
                    remediable=self.remediable,
                    evidence=group["IpPermissions"],
                    account_id=account_id
                ))

        if unevaluated_list:
            status = CheckStatus.PARTIAL
        elif findings_list:
            status = CheckStatus.VIOLATIONS
        else:
            status = CheckStatus.EVALUATED

        return CheckResult(
            status=status,
            findings=findings_list,
            control_id=self.control_id,
            error=None,
            unevaluated=[],
            )