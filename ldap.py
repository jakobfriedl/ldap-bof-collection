import conquest
import os.path
import re
import random

SCRIPT_DIR = os.path.dirname(__file__)

# Helper function to determine if input is a standard username or a distinguished name
def input_type(s):
    if s and re.match(r'^(?:[A-Z]+=[^,]+)(?:,(?:[A-Z]+=[^,]+))*$', s, re.IGNORECASE):
        return 1    # Distinguished name
    return 0        # Username

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# GET COMMANDS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getusers = (
    conquest.createCommand(name="get-users", description="List all users in the domain.", example="get-users -ou \"OU=Users,DC=conquest,DC=local\" --dc dc01.conquest.local -a description,mail",
                           message="Tasked agent to enumerate conquest users.", mitre=["T1087.002"])
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagString("--attributes", "attributes", "Comma-separated list of attributes to retrieve.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                ou := conquest.get_string(args, 0),
                dc := conquest.get_string(args, 1),
                attributes := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-users.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zziz", [
                    ou,             # z: OU path
                    dc,             # z: Domain Controller
                    ldaps,          # i: Use LDAPS
                    attributes      # z: Attributes
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getcomputers = (
    conquest.createCommand(name="get-computers", description="List all computers in the domain.", example="get-computers -ou \"OU=Computers,DC=conquest,DC=local\" --dc dc01.conquest.local -a description,operatingSystem",
                           message="Tasked agent to enumerate conquest computers.", mitre=["T1087.002"])
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagString("--attributes", "attributes", "Comma-separated list of attributes to retrieve.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                ou := conquest.get_string(args, 0),
                dc := conquest.get_string(args, 1),
                attributes := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-computers.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zziz", [
                    ou,             # z: OU path
                    dc,             # z: Domain Controller
                    ldaps,          # i: Use LDAPS
                    attributes      # z: Attributes
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getgroups = (
    conquest.createCommand(name="get-groups", description="List all groups in the domain.", example="get-groups -ou \"OU=Groups,DC=conquest,DC=local\" --dc dc01.conquest.local -a description,member",
                           message="Tasked agent to enumerate conquest groups.", mitre=["T1069.002"])
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagString("--attributes", "attributes", "Comma-separated list of attributes to retrieve.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                ou := conquest.get_string(args, 0),
                dc := conquest.get_string(args, 1),
                attributes := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-groups.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zziz", [
                    ou,             # z: OU path
                    dc,             # z: Domain Controller
                    ldaps,          # i: Use LDAPS
                    attributes      # z: Attributes
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getusergroups = (
    conquest.createCommand(name="get-usergroups", description="List all groups a user is a member of.", example="get-usergroups julius -ou \"OU=Users,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to query user group memberships.", mitre=["T1069.002"])
            .addArgString("user", "Username or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                user := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-usergroups.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzi", [
                    user,                   # z: Username
                    input_type(user),       # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getgroupmembers = (
    conquest.createCommand(name="get-groupmembers", description="List all members of a group.", example="get-groupmembers \"Domain Admins\" -ou \"OU=Groups,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to query group members.", mitre=["T1069.002"])
            .addArgString("group", "Group name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .setHandler(lambda agentId, cmdline, args: (
                group := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-groupmembers.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizz", [
                    group,                  # z: Group name
                    input_type(group),      # i: Is DN
                    ou,                     # z: OU path
                    dc                      # z: Domain Controller
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getobject = (
    conquest.createCommand(name="get-object", description="Get all attributes of an object.", example="get-object julius -ou \"OU=Users,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to query object attributes.", mitre=["T1087.002"])
            .addArgString("target", "Object name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-object.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getdomaininfo = (
    conquest.createCommand(name="get-domaininfo", description="Get conquest information from rootDSE.", example="get-domaininfo --dc dc01.conquest.local",
                           message="Tasked agent to query conquest information.", mitre=["T1087.002"])
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                dc := conquest.get_string(args, 0),
                ldaps := int(conquest.get_bool(args, 1)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-domaininfo.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zi", [
                    dc,             # z: Domain Controller
                    ldaps           # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getmaq = (
    conquest.createCommand(name="get-maq", description="Get machine account quota (ms-DS-MachineAccountQuota).", example="get-maq --dc dc01.conquest.local",
                           message="Tasked agent to query machine account quota.", mitre=["T1087.002"])
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                dc := conquest.get_string(args, 0),
                ldaps := int(conquest.get_bool(args, 1)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-maq.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zi", [
                    dc,             # z: Domain Controller
                    ldaps           # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getwritable = (
    conquest.createCommand(name="get-writable", description="Find objects you have write access to.", example="get-writable -ou \"OU=Projects,DC=conquest,DC=local\" --dc dc01.conquest.local --detailed",
                           message="Tasked agent to find writable objects.", mitre=["T1087.002"])
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .addFlagBool("--detailed", "Show detailed output.")
            .setHandler(lambda agentId, cmdline, args: (
                ou := conquest.get_string(args, 0),
                dc := conquest.get_string(args, 1),
                ldaps := int(conquest.get_bool(args, 2)),
                detailed := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-writable.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zzii", [
                    ou,             # z: OU path
                    dc,             # z: Domain Controller
                    ldaps,          # i: Use LDAPS
                    detailed        # i: Detailed output
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getdelegation = (
    conquest.createCommand(name="get-delegation", description="Get delegation configuration for an object.", example="get-delegation machine01$ -ou \"OU=Computers,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to query delegation configuration.", mitre=["T1087.002"])
            .addArgString("target", "Object name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-delegation.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getuac = (
    conquest.createCommand(name="get-uac", description="Get UAC flags for an object.", example="get-uac julius -ou \"OU=Users,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to query UAC flags.", mitre=["T1087.002"])
            .addArgString("target", "Object name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-uac.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getattribute = (
    conquest.createCommand(name="get-attribute", description="Get specific attribute values.", example="get-attribute julius objectSid,mail,description -ou \"OU=Users,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to query attribute values.", mitre=["T1087.002"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("attributes", "Comma-separated list of attribute names.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                attributes := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-attribute.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    attributes,             # z: Attributes
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getspn = (
    conquest.createCommand(name="get-spn", description="Get SPNs for an object.", example="get-spn machine01$ -ou \"OU=Computers,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to query SPNs.", mitre=["T1087.002"])
            .addArgString("target", "Object name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-spn.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getacl = (
    conquest.createCommand(name="get-acl", description="Get ACL/security descriptor for an object.", example="get-acl julius -ou \"OU=Users,DC=conquest,DC=local\" --dc dc01.conquest.local --resolve",
                           message="Tasked agent to query ACL.", mitre=["T1087.002"])
            .addArgString("target", "Object name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .addFlagBool("--resolve", "Resolve SID names.")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),
                resolve := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-acl.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzii", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps,                  # i: Use LDAPS
                    resolve                 # i: Resolve SID names
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_getrbcd = (
    conquest.createCommand(name="get-rbcd", description="Get RBCD configuration for an object.", example="get-rbcd somecomputer$ -ou \"OU=Computers,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to query RBCD configuration.", mitre=["T1087.002"])
            .addArgString("target", "Object name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/get-rbcd.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# ADD COMMANDS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_adduser = (
    conquest.createCommand(name="add-user", description="Add a user to the domain.", example="add-user julius 'P@ssw0rd!' -fn Jane -ln Doe -email julius@conquest.local -ou \"OU=Users,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to add a domain user.", mitre=["T1136.002"])
            .addArgString("username", "Username or DN.", True)
            .addArgString("password", "Password for the user.", True)
            .addFlagString("--fn", "firstname", "First name.")
            .addFlagString("--ln", "lastname", "Last name.")
            .addFlagString("--email", "email", "Email address.")
            .addFlagBool("--disabled", "Create account disabled.")
            .addFlagString("--ou", "path", "Target OU path.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                username := conquest.get_string(args, 0),
                password := conquest.get_string(args, 1),
                firstname := conquest.get_string(args, 2),
                lastname := conquest.get_string(args, 3),
                email := conquest.get_string(args, 4),
                disabled := int(conquest.get_bool(args, 5)),
                ou := conquest.get_string(args, 6),
                dc := conquest.get_string(args, 7),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-user.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzzizzi", [
                    username,               # z: Username
                    input_type(username),   # i: Is DN
                    password,               # z: Password
                    firstname,              # z: First name
                    lastname,               # z: Last name
                    email,                  # z: Email
                    disabled,               # i: Create disabled
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    1                       # i: Use LDAPS (forced)
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addcomputer = (
    conquest.createCommand(name="add-computer", description="Add a computer to the domain.", example="add-computer FAKE01 -p 'Password123!' -ou \"OU=Computers,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to add a domain computer.", mitre=["T1136.002"])
            .addArgString("computer", "Computer name or DN.", True)
            .addArgString("password", "Password for the computer (default: Randomized).")
            .addFlagString("--ou", "path", "Target OU path.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--disabled", "Create account disabled.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                computer := conquest.get_string(args, 0),
                password := conquest.get_string(args, 1) if conquest.get_string(args, 1) else ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*+-=", k=16)),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                disabled := int(conquest.get_bool(args, 4)),
                ldaps := int(conquest.get_bool(args, 5)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-computer.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzii", [
                    computer,               # z: Computer name
                    input_type(computer),   # i: Is DN
                    password,               # z: Password
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    disabled,               # i: Create disabled
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addgroup = (
    conquest.createCommand(name="add-group", description="Add a group to the domain.", example="add-group Stark --desc \"House Stark\" -scope global -ou \"OU=Groups,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to add a domain group.", mitre=["T1136.002"])
            .addArgString("groupname", "Group name or DN.", True)
            .addFlagString("--desc", "description", "Group description.")
            .addFlagString("--type", "type", "Group type: security or distribution.")
            .addFlagString("--scope", "scope", "Group scope: global, domainlocal, or universal.")
            .addFlagString("--ou", "path", "Target OU path.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                groupname := conquest.get_string(args, 0),
                desc := conquest.get_string(args, 1),
                gtype := conquest.get_string(args, 2),
                scope := conquest.get_string(args, 3),
                ou := conquest.get_string(args, 4),
                dc := conquest.get_string(args, 5),
                ldaps := int(conquest.get_bool(args, 6)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-group.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzzzi", [
                    groupname,              # z: Group name
                    input_type(groupname),  # i: Is DN
                    desc,                   # z: Description
                    gtype,                  # z: Group type
                    scope,                  # z: Group scope
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addgroupmember = (
    conquest.createCommand(name="add-groupmember", description="Add a member to a group.", example="add-groupmember Stark julius -ou \"OU=Groups,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to add group member.", mitre=["T1098"])
            .addArgString("group", "Group name or DN.", True)
            .addArgString("member", "Member name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                group := conquest.get_string(args, 0),
                member := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-groupmember.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzi", [
                    group,                  # z: Group name
                    input_type(group),      # i: Is DN
                    member,                 # z: Member name
                    input_type(member),     # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addou = (
    conquest.createCommand(name="add-ou", description="Add an organizational unit.", example="add-ou Research --desc \"Research OU\" --parent \"OU=Departments,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to add an OU.", mitre=["T1136.002"])
            .addArgString("ou_name", "OU name or DN.", True)
            .addFlagString("--desc", "description", "OU description.")
            .addFlagString("--parent", "parent_ou", "Parent OU DN.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                ou_name := conquest.get_string(args, 0),
                desc := conquest.get_string(args, 1),
                parent := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-ou.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    ou_name,                # z: OU name
                    input_type(ou_name),    # i: Is DN
                    desc,                   # z: Description
                    parent,                 # z: Parent OU
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addsidhistory = (
    conquest.createCommand(name="add-sidhistory", description="Add a SID to an object's sidHistory attribute.", example="add-sidhistory julius S-1-5-21-123456789-123456789-123456789-500 --dc dc01.conquest.local",
                           message="Tasked agent to add SID to sidHistory.", mitre=["T1134.005"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("sid_source", "SID string, username, or DN to copy SID from.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                sid_source := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-sidhistory.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    sid_source,                 # z: SID source
                    input_type(sid_source),     # i: Is DN
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addspn = (
    conquest.createCommand(name="add-spn", description="Add an SPN to an object.", example="add-spn machine01 HOST/machine01.conquest.local --dc dc01.conquest.local",
                           message="Tasked agent to add SPN.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("spn", "SPN to add.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                spn := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-spn.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    spn,                    # z: SPN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addattribute = (
    conquest.createCommand(name="add-attribute", description="Add a value to an attribute.", example="add-attribute julius description 'Some description' --dc dc01.conquest.local",
                           message="Tasked agent to add attribute value.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("attribute", "Attribute name.", True)
            .addArgString("value", "Value to add.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                attribute := conquest.get_string(args, 1),
                value := conquest.get_string(args, 2),
                ou := conquest.get_string(args, 3),
                dc := conquest.get_string(args, 4),
                ldaps := int(conquest.get_bool(args, 5)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-attribute.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    attribute,              # z: Attribute name
                    value,                  # z: Value
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_adduac = (
    conquest.createCommand(name="add-uac", description="Add UAC flags to an object.", example="add-uac julius DONT_REQ_PREAUTH --dc dc01.conquest.local",
                           message="Tasked agent to add UAC flags.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("flags", "Comma-separated UAC flags.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                flags := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-uac.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    flags,                  # z: UAC flags
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_adddelegation = (
    conquest.createCommand(name="add-delegation", description="Add a delegation SPN to an object.", example="add-delegation machine01 RestrictedKrbHost/machine01.conquest.local --dc dc01.conquest.local",
                           message="Tasked agent to add delegation SPN.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("spn", "Delegation SPN to add.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                spn := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-delegation.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    spn,                    # z: Delegation SPN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addrbcd = (
    conquest.createCommand(name="add-rbcd", description="Add an RBCD delegation.", example="add-rbcd targetComputer$ principalAccount$ --dc dc01.conquest.local",
                           message="Tasked agent to add RBCD delegation.", mitre=["T1098"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("delegate", "Object allowed to delegate.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                delegate := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-rbcd.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    delegate,                   # z: Delegate object
                    input_type(delegate),       # i: Is DN
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addace = (
    conquest.createCommand(name="add-ace", description="Add an ACE to an object's DACL.", example="add-ace CN=SomeObject,DC=conquest,DC=local julius GenericAll --dc dc01.conquest.local",
                           message="Tasked agent to add ACE.", mitre=["T1222.001"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("trustee", "Trustee name or DN.", True)
            .addArgString("rights", "Access rights (e.g., GenericAll, WriteDacl, DCSync).", True)
            .addFlagString("--type", "ace_type", "ACE type: allow (default), deny.")
            .addFlagString("--flags", "flags", "ACE inheritance flags (e.g., CI,OI).")
            .addFlagString("--guid", "guid", "Object type GUID.")
            .addFlagString("--inherit-guid", "inherit_guid", "Inherited object type GUID.")
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                trustee := conquest.get_string(args, 1),
                rights := conquest.get_string(args, 2),
                ace_type := conquest.get_string(args, 3),
                ace_flags := conquest.get_string(args, 4),
                guid := conquest.get_string(args, 5),
                inherit_guid := conquest.get_string(args, 6),
                ou := conquest.get_string(args, 7),
                dc := conquest.get_string(args, 8),
                ldaps := int(conquest.get_bool(args, 9)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-ace.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzzzzzzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    trustee,                    # z: Trustee
                    input_type(trustee),        # i: Is DN
                    rights,                     # z: Access rights
                    ace_type,                   # z: ACE type
                    ace_flags,                  # z: ACE flags
                    guid,                       # z: Object type GUID
                    inherit_guid,               # z: Inherited object type GUID
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ADD MACROS

cmd_addgenericall = (
    conquest.createCommand(name="add-genericall", description="Add a GenericAll ACE to an object's DACL.", example="add-genericall CN=SomeObject,DC=conquest,DC=local julius --dc dc01.conquest.local",
                           message="Tasked agent to add GenericAll ACE.", mitre=["T1222.001"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("trustee", "Trustee name or DN.", True)
            .addFlagString("--type", "ace_type", "ACE type: allow (default), deny.")
            .addFlagString("--flags", "flags", "ACE inheritance flags (e.g., CI,OI).")
            .addFlagString("--guid", "guid", "Object type GUID.")
            .addFlagString("--inherit-guid", "inherit_guid", "Inherited object type GUID.")
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                trustee := conquest.get_string(args, 1),
                ace_type := conquest.get_string(args, 2),
                ace_flags := conquest.get_string(args, 3),
                guid := conquest.get_string(args, 4),
                inherit_guid := conquest.get_string(args, 5),
                ou := conquest.get_string(args, 6),
                dc := conquest.get_string(args, 7),
                ldaps := int(conquest.get_bool(args, 8)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-ace.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzzzzzzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    trustee,                    # z: Trustee
                    input_type(trustee),        # i: Is DN
                    "GenericAll",               # z: Access rights (preset)
                    ace_type,                   # z: ACE type
                    ace_flags,                  # z: ACE flags
                    guid,                       # z: Object type GUID
                    inherit_guid,               # z: Inherited object type GUID
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addgenericwrite = (
    conquest.createCommand(name="add-genericwrite", description="Add a GenericWrite ACE to an object's DACL.", example="add-genericwrite CN=SomeObject,DC=conquest,DC=local julius --dc dc01.conquest.local",
                           message="Tasked agent to add GenericWrite ACE.", mitre=["T1222.001"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("trustee", "Trustee name or DN.", True)
            .addFlagString("--type", "ace_type", "ACE type: allow (default), deny.")
            .addFlagString("--flags", "flags", "ACE inheritance flags (e.g., CI,OI).")
            .addFlagString("--guid", "guid", "Object type GUID.")
            .addFlagString("--inherit-guid", "inherit_guid", "Inherited object type GUID.")
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                trustee := conquest.get_string(args, 1),
                ace_type := conquest.get_string(args, 2),
                ace_flags := conquest.get_string(args, 3),
                guid := conquest.get_string(args, 4),
                inherit_guid := conquest.get_string(args, 5),
                ou := conquest.get_string(args, 6),
                dc := conquest.get_string(args, 7),
                ldaps := int(conquest.get_bool(args, 8)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-ace.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzzzzzzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    trustee,                    # z: Trustee
                    input_type(trustee),        # i: Is DN
                    "GenericWrite",             # z: Access rights (preset)
                    ace_type,                   # z: ACE type
                    ace_flags,                  # z: ACE flags
                    guid,                       # z: Object type GUID
                    inherit_guid,               # z: Inherited object type GUID
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_adddcsync = (
    conquest.createCommand(name="add--dcsync", description="Add a DCSync ACE to an object's DACL.", example="add--dcsync DC=conquest,DC=local julius --dc dc01.conquest.local",
                           message="Tasked agent to add DCSync ACE.", mitre=["T1222.001"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("trustee", "Trustee name or DN.", True)
            .addFlagString("--type", "ace_type", "ACE type: allow (default), deny.")
            .addFlagString("--flags", "flags", "ACE inheritance flags (e.g., CI,OI).")
            .addFlagString("--guid", "guid", "Object type GUID.")
            .addFlagString("--inherit-guid", "inherit_guid", "Inherited object type GUID.")
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                trustee := conquest.get_string(args, 1),
                ace_type := conquest.get_string(args, 2),
                ace_flags := conquest.get_string(args, 3),
                guid := conquest.get_string(args, 4),
                inherit_guid := conquest.get_string(args, 5),
                ou := conquest.get_string(args, 6),
                dc := conquest.get_string(args, 7),
                ldaps := int(conquest.get_bool(args, 8)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-ace.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzzzzzzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    trustee,                    # z: Trustee
                    input_type(trustee),        # i: Is DN
                    "DCSync",                   # z: Access rights (preset)
                    ace_type,                   # z: ACE type
                    ace_flags,                  # z: ACE flags
                    guid,                       # z: Object type GUID
                    inherit_guid,               # z: Inherited object type GUID
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addasreproastable = (
    conquest.createCommand(name="add-asreproastable", description="Make a user AS-REP roastable (set DONT_REQ_PREAUTH).", example="add-asreproastable julius --dc dc01.conquest.local",
                           message="Tasked agent to set DONT_REQ_PREAUTH.", mitre=["T1098"])
            .addArgString("target", "Target user name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-uac.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    "DONT_REQ_PREAUTH",     # z: UAC flags (preset)
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addunconstrained = (
    conquest.createCommand(name="add-unconstrained", description="Enable unconstrained delegation on an object.", example="add-unconstrained machine01$ --dc dc01.conquest.local",
                           message="Tasked agent to enable unconstrained delegation.", mitre=["T1098"])
            .addArgString("target", "Target object name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-uac.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    "TRUSTED_FOR_DELEGATION",   # z: UAC flags (preset)
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_addconstrained = (
    conquest.createCommand(name="add-constrained", description="Set/replace delegation SPNs (constrained delegation).", example="add-constrained machine01$ RestrictedKrbHost/machine01.conquest.local --dc dc01.conquest.local",
                           message="Tasked agent to set constrained delegation.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("spn", "Delegation SPN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                spn := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/add-delegation.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    spn,                    # z: Delegation SPN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# SET COMMANDS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_setpassword = (
    conquest.createCommand(name="set-password", description="Set/reset a user's password.", example="set-password julius 'N3wP@ssw0rd!' -old 'OldP@ss' --dc dc01.conquest.local",
                           message="Tasked agent to set password.", mitre=["T1098"])
            .addArgString("target", "User name or DN.", True)
            .addArgString("password", "New password.", True)
            .addFlagString("--old", "old_password", "Old password (for self-service change, omit for admin reset).")
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                password := conquest.get_string(args, 1),
                old_password := conquest.get_string(args, 2),
                ou := conquest.get_string(args, 3),
                dc := conquest.get_string(args, 4),
                ldaps := int(conquest.get_bool(args, 5)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/set-password.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzzi", [
                    target,                 # z: Target user
                    input_type(target),     # i: Is DN
                    password,               # z: New password
                    old_password,           # z: Old password
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS 
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_setspn = (
    conquest.createCommand(name="set-spn", description="Set/replace all SPNs on an object.", example="set-spn machine01$ HOST/machine01.conquest.local --dc dc01.conquest.local --ldaps",
                           message="Tasked agent to set SPN.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("spn", "SPN to set (replaces all existing).", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                spn := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/set-spn.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    spn,                    # z: SPN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_setdelegation = (
    conquest.createCommand(name="set-delegation", description="Set/replace delegation SPNs.", example="set-delegation appsvc RestrictedKrbHost/appsvc.conquest.local --dc dc01.conquest.local --ldaps",
                           message="Tasked agent to set delegation.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("spn", "Delegation SPN (replaces all existing).", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                spn := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/set-delegation.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    spn,                    # z: Delegation SPN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_setattribute = (
    conquest.createCommand(name="set-attribute", description="Set/replace an attribute value.", example="set-attribute julius description 'New description' --dc dc01.conquest.local",
                           message="Tasked agent to set attribute.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("attribute", "Attribute name.", True)
            .addArgString("value", "Value to set.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                attribute := conquest.get_string(args, 1),
                value := conquest.get_string(args, 2),
                ou := conquest.get_string(args, 3),
                dc := conquest.get_string(args, 4),
                ldaps := int(conquest.get_bool(args, 5)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/set-attribute.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    attribute,              # z: Attribute name
                    value,                  # z: Value
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_setuac = (
    conquest.createCommand(name="set-uac", description="Set UAC flags (replaces all).", example="set-uac julius DONT_EXPIRE_PASSWD --dc dc01.conquest.local",
                           message="Tasked agent to set UAC flags.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("flags", "Comma-separated UAC flags (replaces all).", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                flags := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/set-uac.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    flags,                  # z: UAC flags
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_setowner = (
    conquest.createCommand(name="set-owner", description="Set the owner of an object (requires WriteOwner).", example="set-owner CN=resource,DC=conquest,DC=local CN=julius,DC=conquest,DC=local --dc dc01.conquest.local",
                           message="Tasked agent to set object owner.", mitre=["T1222.001"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("owner", "New owner name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                owner := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/set-owner.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    owner,                  # z: New owner
                    input_type(owner),      # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# MOVE COMMANDS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_moveobject = (
    conquest.createCommand(name="move-object", description="Move an object to a different OU.", example="move-object julius \"OU=Managers,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to move object.", mitre=["T1098"])
            .addArgString("object", "Object name or DN to move.", True)
            .addArgString("destination", "Destination OU DN.", True)
            .addFlagString("--name", "name", "New name for the object.")
            .addFlagString("--ou", "path", "OU path to search for object.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                obj := conquest.get_string(args, 0),
                destination := conquest.get_string(args, 1),
                new_name := conquest.get_string(args, 2),
                ou := conquest.get_string(args, 3),
                dc := conquest.get_string(args, 4),
                ldaps := int(conquest.get_bool(args, 5)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/move-object.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzzi", [
                    obj,                    # z: Object to move
                    input_type(obj),        # i: Is DN
                    destination,            # z: Destination OU
                    new_name,               # z: New name
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# REMOVE COMMANDS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_removegroupmember = (
    conquest.createCommand(name="remove-groupmember", description="Remove a member from a group.", example="remove-groupmember Stark julius --dc dc01.conquest.local",
                           message="Tasked agent to remove group member.", mitre=["T1098"])
            .addArgString("group", "Group name or DN.", True)
            .addArgString("member", "Member name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                group := conquest.get_string(args, 0),
                member := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-groupmember.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzi", [
                    group,                  # z: Group name
                    input_type(group),      # i: Is DN
                    member,                 # z: Member name
                    input_type(member),     # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_removeobject = (
    conquest.createCommand(name="remove-object", description="Remove an object from the domain.", example="remove-object julius -ou \"OU=Users,DC=conquest,DC=local\" --dc dc01.conquest.local",
                           message="Tasked agent to remove object.", mitre=["T1098"])
            .addArgString("object", "Object name or DN.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                obj := conquest.get_string(args, 0),
                ou := conquest.get_string(args, 1),
                dc := conquest.get_string(args, 2),
                ldaps := int(conquest.get_bool(args, 3)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-object.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzi", [
                    obj,                    # z: Object
                    input_type(obj),        # i: Is DN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_removespn = (
    conquest.createCommand(name="remove-spn", description="Remove an SPN from an object.", example="remove-spn machine01$ HOST/machine01.conquest.local --dc dc01.conquest.local",
                           message="Tasked agent to remove SPN.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("spn", "SPN to remove.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                spn := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-spn.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    spn,                    # z: SPN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_removedelegation = (
    conquest.createCommand(name="remove-delegation", description="Remove a delegation SPN.", example="remove-delegation machine01$ RestrictedKrbHost/machine01.conquest.local --dc dc01.conquest.local",
                           message="Tasked agent to remove delegation SPN.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("spn", "Delegation SPN to remove.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                spn := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-delegation.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    spn,                    # z: Delegation SPN
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_removeattribute = (
    conquest.createCommand(name="remove-attribute", description="Remove an attribute or attribute value.", example="remove-attribute julius description -value 'Old description' --dc dc01.conquest.local",
                           message="Tasked agent to remove attribute.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("attribute", "Attribute name.", True)
            .addFlagString("--value", "value", "Specific value to remove (removes entire attribute if not specified).")
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                attribute := conquest.get_string(args, 1),
                value := conquest.get_string(args, 2),
                ou := conquest.get_string(args, 3),
                dc := conquest.get_string(args, 4),
                ldaps := int(conquest.get_bool(args, 5)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-attribute.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    attribute,              # z: Attribute name
                    value,                  # z: Value to remove
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_removeuac = (
    conquest.createCommand(name="remove-uac", description="Remove UAC flags from an object.", example="remove-uac julius DONT_EXPIRE_PASSWD --dc dc01.conquest.local",
                           message="Tasked agent to remove UAC flags.", mitre=["T1098"])
            .addArgString("target", "Object name or DN.", True)
            .addArgString("flags", "Comma-separated UAC flags to remove.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                flags := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-uac.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizzzi", [
                    target,                 # z: Target object
                    input_type(target),     # i: Is DN
                    flags,                  # z: UAC flags
                    ou,                     # z: OU path
                    dc,                     # z: Domain Controller
                    ldaps                   # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_removeace = (
    conquest.createCommand(name="remove-ace", description="Remove an ACE from an object's DACL.", example="remove-ace CN=SomeObject,DC=conquest,DC=local -trustee julius --dc dc01.conquest.local",
                           message="Tasked agent to remove ACE.", mitre=["T1222.001"])
            .addArgString("target", "Target object name or DN.", True)
            .addFlagString("--trustee", "trustee", "Trustee name or DN to match.")
            .addFlagString("--rights", "rights", "Access rights to match (e.g., GenericAll, DCSync).")
            .addFlagString("--type", "ace_type", "ACE type to match: allow, deny.")
            .addFlagInt("--index", "ace_index", "ACE index to remove (use get-acl to find index).")
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                trustee := conquest.get_string(args, 1),
                rights := conquest.get_string(args, 2),
                ace_type := conquest.get_string(args, 3),
                ace_index := conquest.get_int(args, 4),
                ou := conquest.get_string(args, 5),
                dc := conquest.get_string(args, 6),
                ldaps := int(conquest.get_bool(args, 7)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-ace.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzizzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    trustee,                    # z: Trustee
                    input_type(trustee),        # i: Is DN
                    rights,                     # z: Access rights
                    ace_type,                   # z: ACE type
                    ace_index,                  # i: ACE index
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_removerbcd = (
    conquest.createCommand(name="remove-rbcd", description="Remove an RBCD delegation.", example="remove-rbcd targetComputer principalAccount --dc dc01.conquest.local",
                           message="Tasked agent to remove RBCD delegation.", mitre=["T1098"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("delegate", "Object to remove from delegation.", True)
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                delegate := conquest.get_string(args, 1),
                ou := conquest.get_string(args, 2),
                dc := conquest.get_string(args, 3),
                ldaps := int(conquest.get_bool(args, 4)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-rbcd.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    delegate,                   # z: Delegate object
                    input_type(delegate),       # i: Is DN
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# REMOVE MACROS

cmd_removedcsync = (
    conquest.createCommand(name="remove--dcsync", description="Remove a DCSync ACE from an object's DACL.", example="remove--dcsync DC=conquest,DC=local julius --dc dc01.conquest.local",
                           message="Tasked agent to remove DCSync ACE.", mitre=["T1222.001"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("trustee", "Trustee name or DN.", True)
            .addFlagString("--type", "ace_type", "ACE type to match: allow, deny.")
            .addFlagInt("--index", "ace_index", "ACE index to remove (use get-acl to find index).")
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                trustee := conquest.get_string(args, 1),
                ace_type := conquest.get_string(args, 2),
                ace_index := conquest.get_int(args, 3),
                ou := conquest.get_string(args, 4),
                dc := conquest.get_string(args, 5),
                ldaps := int(conquest.get_bool(args, 6)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-ace.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzizzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    trustee,                    # z: Trustee
                    input_type(trustee),        # i: Is DN
                    "DCSync",                   # z: Access rights (preset)
                    ace_type,                   # z: ACE type
                    ace_index,                  # i: ACE index
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_removegenericwrite = (
    conquest.createCommand(name="remove-genericwrite", description="Remove a GenericWrite ACE from an object's DACL.", example="remove-genericwrite CN=SomeObject,DC=conquest,DC=local julius --dc dc01.conquest.local",
                           message="Tasked agent to remove GenericWrite ACE.", mitre=["T1222.001"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("trustee", "Trustee name or DN.", True)
            .addFlagString("--type", "ace_type", "ACE type to match: allow, deny.")
            .addFlagInt("--index", "ace_index", "ACE index to remove (use get-acl to find index).")
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                trustee := conquest.get_string(args, 1),
                ace_type := conquest.get_string(args, 2),
                ace_index := conquest.get_int(args, 3),
                ou := conquest.get_string(args, 4),
                dc := conquest.get_string(args, 5),
                ldaps := int(conquest.get_bool(args, 6)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-ace.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzizzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    trustee,                    # z: Trustee
                    input_type(trustee),        # i: Is DN
                    "GenericWrite",             # z: Access rights (preset)
                    ace_type,                   # z: ACE type
                    ace_index,                  # i: ACE index
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

cmd_removegenericall = (
    conquest.createCommand(name="remove-genericall", description="Remove a GenericAll ACE from an object's DACL.", example="remove-genericall CN=SomeObject,DC=conquest,DC=local julius --dc dc01.conquest.local",
                           message="Tasked agent to remove GenericAll ACE.", mitre=["T1222.001"])
            .addArgString("target", "Target object name or DN.", True)
            .addArgString("trustee", "Trustee name or DN.", True)
            .addFlagString("--type", "ace_type", "ACE type to match: allow, deny.")
            .addFlagInt("--index", "ace_index", "ACE index to remove (use get-acl to find index).")
            .addFlagString("--ou", "path", "OU path to search.")
            .addFlagString("--dc", "fqdn", "FQDN of the domain controller.")
            .addFlagBool("--ldaps", "Use LDAPS (port 636).")
            .setHandler(lambda agentId, cmdline, args: (
                target := conquest.get_string(args, 0),
                trustee := conquest.get_string(args, 1),
                ace_type := conquest.get_string(args, 2),
                ace_index := conquest.get_int(args, 3),
                ou := conquest.get_string(args, 4),
                dc := conquest.get_string(args, 5),
                ldaps := int(conquest.get_bool(args, 6)),

                bof := os.path.join(SCRIPT_DIR, f"_bin/LDAP/remove-ace.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("zizizzizzi", [
                    target,                     # z: Target object
                    input_type(target),         # i: Is DN
                    trustee,                    # z: Trustee
                    input_type(trustee),        # i: Is DN
                    "GenericAll",               # z: Access rights (preset)
                    ace_type,                   # z: ACE type
                    ace_index,                  # i: ACE index
                    ou,                         # z: OU path
                    dc,                         # z: Domain Controller
                    ldaps                       # i: Use LDAPS
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("ldap operations")
