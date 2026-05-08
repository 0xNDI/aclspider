import argparse
import itertools
import json
import ntpath
import os
import queue
import random
import string
import sys
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import contextmanager

from impacket.dcerpc.v5 import lsad, lsat, rpcrt, samr, transport
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.lsat import DCERPCSessionError
from impacket.ldap import ldaptypes
from impacket.nt_errors import STATUS_NONE_MAPPED, STATUS_SOME_NOT_MAPPED
from impacket.smb3structs import (
    DACL_SECURITY_INFORMATION,
    FILE_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_READ_ATTRIBUTES,
    GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION,
    READ_CONTROL,
    SMB2_0_INFO_SECURITY,
    SMB2_SEC_INFO_00,
)
from impacket.smbconnection import SessionError, SMBConnection

_tree_cache: dict[int, dict[str, int]] = {}


def _get_tree(conn: SMBConnection, share: str) -> int:
    cid = id(conn)
    if cid not in _tree_cache:
        _tree_cache[cid] = {}
    if share not in _tree_cache[cid]:
        _tree_cache[cid][share] = conn.connectTree(share)
    return _tree_cache[cid][share]


SKIP_SIDS = {
    "S-1-5-18",  # SYSTEM
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-3-0",  # CREATOR OWNER
    "S-1-3-4",  # CREATOR OWNER SERVER
    "S-1-1-0",  # Everyone
}

SKIP_DOMAIN_RIDS = {
    "512",  # Domain Admins
    "518",  # Schema Admins
    "519",  # Enterprise Admins
    "520",  # Group Policy Creator Owners
}

WRITE_DIR_MASKS = [
    (0x0002, "FILE_ADD_FILE"),
    (0x0004, "FILE_ADD_SUBDIRECTORY"),
    (0x0010, "FILE_WRITE_EA"),
    (0x0040, "FILE_DELETE_CHILD"),
    (0x0100, "FILE_WRITE_ATTRIBUTES"),
]

ALL_DIR_MASKS = [
    (0x0001, "FILE_LIST_DIRECTORY"),
    (0x0002, "FILE_ADD_FILE"),
    (0x0004, "FILE_ADD_SUBDIRECTORY"),
    (0x0008, "FILE_READ_EA"),
    (0x0010, "FILE_WRITE_EA"),
    (0x0020, "FILE_TRAVERSE"),
    (0x0040, "FILE_DELETE_CHILD"),
    (0x0080, "FILE_READ_ATTRIBUTES"),
    (0x0100, "FILE_WRITE_ATTRIBUTES"),
]

GENERIC_FLAGS = [
    ("GENERIC_READ", 0x80000000),
    ("GENERIC_WRITE", 0x40000000),
    ("GENERIC_EXECUTE", 0x20000000),
    ("GENERIC_ALL", 0x10000000),
    ("MAXIMUM_ALLOWED", 0x02000000),
    ("ACCESS_SYSTEM_SECURITY", 0x01000000),
    ("WRITE_OWNER", 0x00080000),
    ("WRITE_DACL", 0x00040000),
    ("DELETE", 0x00010000),
    ("READ_CONTROL", 0x00020000),
    ("SYNCHRONIZE", 0x00100000),
]

WRITE_GENERIC = {"GENERIC_WRITE", "GENERIC_ALL", "MAXIMUM_ALLOWED", "WRITE_OWNER", "WRITE_DACL", "DELETE"}

ANSI_BOLD = "\x1b[1m"
ANSI_RED = "\x1b[91m"
ANSI_YELLOW = "\x1b[93m"
ANSI_GREEN = "\x1b[92m"
ANSI_CYAN = "\x1b[96m"
ANSI_RESET = "\x1b[0m"


def bold(s: str, color: bool = True) -> str:
    return f"{ANSI_BOLD}{s}{ANSI_RESET}" if color else s


def red(s: str, color: bool = True) -> str:
    return f"{ANSI_RED}{s}{ANSI_RESET}" if color else s


def yellow(s: str, color: bool = True) -> str:
    return f"{ANSI_YELLOW}{s}{ANSI_RESET}" if color else s


def green(s: str, color: bool = True) -> str:
    return f"{ANSI_GREEN}{s}{ANSI_RESET}" if color else s


def cyan(s: str, color: bool = True) -> str:
    return f"{ANSI_CYAN}{s}{ANSI_RESET}" if color else s


class SIDResolver:
    def __init__(self, smb_client: SMBConnection):
        self._smb = smb_client
        self._dce = self._get_binding()
        self._dce.connect()
        self._dce.bind(lsat.MSRPC_UUID_LSAT)
        self.cache: dict[str, str] = {}

    def _get_binding(self) -> rpcrt.DCERPC_v5:
        rt = transport.SMBTransport(445, filename="lsarpc")
        rt.set_smb_connection(self._smb)
        return rt.get_dce_rpc()

    def _open_policy(self):
        resp = lsad.hLsarOpenPolicy2(self._dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        return resp["PolicyHandle"]

    def resolve_sids(self, sids: set[str]) -> None:
        unresolved = [s for s in sids if s not in self.cache]
        if not unresolved:
            return
        try:
            policy = self._open_policy()
            try:
                resp = lsat.hLsarLookupSids(
                    self._dce,
                    policy,
                    unresolved,
                    lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta,
                )
            except DCERPCSessionError as e:
                if e.error_code == STATUS_SOME_NOT_MAPPED and e.packet:
                    resp = e.packet
                elif e.error_code == STATUS_NONE_MAPPED:
                    return
                else:
                    raise
            for i, item in enumerate(resp["TranslatedNames"]["Names"]):
                domain = resp["ReferencedDomains"]["Domains"][item["DomainIndex"]]["Name"]
                if not item["Name"]:
                    prefix = (domain + "\\") if domain else ""
                    cur = f"{prefix}Unknown (RID={unresolved[i].split('-')[-1]})"
                elif not domain:
                    cur = str(item["Name"])
                else:
                    cur = f"{domain}\\{item['Name']}"
                self.cache[unresolved[i]] = cur
        except Exception:
            pass

    def lookup_names(self, names: list[str]) -> dict[str, str]:
        try:
            policy = self._open_policy()
            resp = lsat.hLsarLookupNames(self._dce, policy, names)
            result = {}
            domains = resp["ReferencedDomains"]["Domains"]
            for i, item in enumerate(resp["TranslatedSids"]["Sids"]):
                didx = item["DomainIndex"]
                if 0 <= didx < len(domains):
                    domain_sid = domains[didx]["Sid"].formatCanonical()
                    rid = item["RelativeId"]
                    result[names[i]] = f"{domain_sid}-{rid}"
            return result
        except Exception:
            return {}

    def get(self, sid: str) -> str:
        if sid not in self.cache:
            self.resolve_sids({sid})
        return self.cache.get(sid, sid)


def connect_smb(args) -> SMBConnection | None:
    try:
        conn = SMBConnection(
            remoteName=args.host,
            remoteHost=args.host,
            sess_port=int(args.port),
            timeout=10,
        )
    except Exception as e:
        print(f"[-] Connection failed: {e}", file=sys.stderr)
        return None

    lm_hash = ""
    nt_hash = ""
    if args.hashes:
        parts = args.hashes.split(":")
        if len(parts) == 2:
            lm_hash, nt_hash = parts
        else:
            nt_hash = parts[0]
            lm_hash = "aad3b435b51404eeaad3b435b51404ee"

    try:
        if args.kerberos:
            if args.ccache:
                os.environ["KRB5CCNAME"] = args.ccache
            conn.kerberosLogin(
                user=args.username or "",
                password=args.password or "",
                domain=args.domain or "",
                lmhash=lm_hash,
                nthash=nt_hash,
                aesKey=args.aes_key or "",
                kdcHost=args.dc_ip,
                useCache=bool(args.ccache),
            )
        else:
            conn.login(
                user=args.username or "",
                password=args.password or "",
                domain=args.domain or "",
                lmhash=lm_hash,
                nthash=nt_hash,
            )
    except SessionError as e:
        print(f"[-] Authentication failed: {e}", file=sys.stderr)
        return None

    return conn


def get_user_groups_samr(conn: SMBConnection, domain: str, username: str, verbose: bool = False) -> list[str]:
    sids = []
    try:
        rt = transport.SMBTransport(conn.getRemoteHost(), filename="samr")
        rt.set_smb_connection(conn)
        dce = rt.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]

        domain_sid = None
        domain_handle = None
        for d in domains:
            if d["Name"].lower() == domain.lower():
                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, d["Name"])
                domain_sid = resp["DomainId"].formatCanonical()
                resp = samr.hSamrOpenDomain(dce, server_handle, domainId=resp["DomainId"])
                domain_handle = resp["DomainHandle"]
                break

        if domain_handle is None:
            for d in domains:
                if d["Name"].lower() != "builtin":
                    resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, d["Name"])
                    domain_sid = resp["DomainId"].formatCanonical()
                    resp = samr.hSamrOpenDomain(dce, server_handle, domainId=resp["DomainId"])
                    domain_handle = resp["DomainHandle"]
                    break

        if domain_handle is None:
            if verbose:
                print("[!] Could not find domain in SAMR", file=sys.stderr)
            return sids

        resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
        user_rid = resp["RelativeIds"]["Element"][0]["Data"]
        user_sid = f"{domain_sid}-{user_rid}"
        sids.append(user_sid)

        resp = samr.hSamrOpenUser(dce, domain_handle, userId=user_rid)
        user_handle = resp["UserHandle"]

        resp = samr.hSamrGetGroupsForUser(dce, user_handle)
        for group in resp["Groups"]["Groups"]:
            group_rid = group["RelativeId"]
            sids.append(f"{domain_sid}-{group_rid}")

        samr.hSamrCloseHandle(dce, user_handle)

        resp = samr.hSamrOpenDomain(
            dce, server_handle, domainId=samr.hSamrLookupDomainInSamServer(dce, server_handle, "Builtin")["DomainId"]
        )
        builtin_handle = resp["DomainHandle"]

        user_sid_obj = samr.RPC_SID()
        user_sid_obj.fromCanonical(user_sid)
        try:
            resp = samr.hSamrGetAliasMembership(
                dce, builtin_handle, [user_sid_obj] + [samr.RPC_SID().fromCanonical(s) or s for s in sids[1:]]
            )
            builtin_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, "Builtin")["DomainId"].formatCanonical()
            for rid in resp["Membership"]["Element"]:
                sids.append(f"{builtin_sid}-{rid['Data']}")
        except Exception:
            pass

        try:
            sid_objs = []
            for s in sids:
                obj = samr.RPC_SID()
                obj.fromCanonical(s)
                sid_objs.append(obj)
            resp = samr.hSamrGetAliasMembership(dce, domain_handle, sid_objs)
            for rid in resp["Membership"]["Element"]:
                sids.append(f"{domain_sid}-{rid['Data']}")
        except Exception:
            pass

        if verbose:
            print(f"[*] Resolved {len(sids)} SIDs for {domain}\\{username} via SAMR")

        dce.disconnect()
    except Exception as e:
        if verbose:
            print(f"[!] SAMR group enumeration failed: {e}", file=sys.stderr)

    return list(set(sids))


def get_acl(conn: SMBConnection, share: str, path: str, is_dir: bool) -> bytes | None:
    try:
        tree_id = _get_tree(conn, share)
        file_id = conn.getSMBServer().create(
            tree_id,
            path,
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            0,
            FILE_DIRECTORY_FILE if is_dir else 0,
            FILE_OPEN,
            0,
        )
        raw = conn.getSMBServer().queryInfo(
            tree_id,
            file_id,
            infoType=SMB2_0_INFO_SECURITY,
            fileInfoClass=SMB2_SEC_INFO_00,
            additionalInformation=(OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION),
            flags=0,
        )
        conn.getSMBServer().close(tree_id, file_id)
        return raw
    except Exception:
        return None


def parse_acl(raw: bytes, is_dir: bool) -> list[dict]:
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd.fromString(raw)
    aces = []
    try:
        dacl = sd["Dacl"]["Data"]
    except Exception:
        return aces

    for ace in dacl:
        try:
            sid = ace["Ace"]["Sid"].formatCanonical()
        except Exception:
            continue
        try:
            ace_type = ace["TypeName"]
        except Exception:
            ace_type = "ACCESS_ALLOWED_ACE"
        try:
            mask_val = ace["Ace"]["Mask"]["Mask"]
        except Exception:
            mask_val = 0

        flags = []
        masks = (
            ALL_DIR_MASKS
            if is_dir
            else [
                (0x0001, "FILE_READ_DATA"),
                (0x0002, "FILE_WRITE_DATA"),
                (0x0004, "FILE_APPEND_DATA"),
                (0x0008, "FILE_READ_EA"),
                (0x0010, "FILE_WRITE_EA"),
                (0x0020, "FILE_EXECUTE"),
                (0x0080, "FILE_READ_ATTRIBUTES"),
                (0x0100, "FILE_WRITE_ATTRIBUTES"),
            ]
        )
        for bit, name in masks:
            if mask_val & bit:
                flags.append(name)
        for name, bit in GENERIC_FLAGS:
            if mask_val & bit:
                flags.append(name)

        if flags:
            aces.append(
                {
                    "sid": sid,
                    "type": ace_type,
                    "flags": flags,
                    "mask": mask_val,
                }
            )
    return aces


def is_write_ace(ace: dict) -> bool:
    write_bits = {name for _, name in WRITE_DIR_MASKS}
    return bool((set(ace["flags"]) & write_bits) or (set(ace["flags"]) & WRITE_GENERIC))


def list_shares(conn: SMBConnection) -> list[str]:
    try:
        shares = conn.listShares()
        return [s["shi1_netname"][:-1] for s in shares]
    except Exception as e:
        print(f"[-] Could not list shares: {e}", file=sys.stderr)
        return []


def test_write_access(conn: SMBConnection, share: str, path: str) -> bool:
    name = "~aclspider_" + "".join(random.choices(string.ascii_lowercase, k=6)) + ".tmp"
    remote_path = ntpath.join(path, name) if path else name
    try:
        tree_id = _get_tree(conn, share)
        smb = conn.getSMBServer()
        fid = smb.create(
            tree_id,
            remote_path,
            0x40000000 | 0x00010000,  # GENERIC_WRITE | DELETE
            0,
            0x00000040 | 0x00001000,  # FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE
            2,  # FILE_CREATE
            0x80,  # FILE_ATTRIBUTE_NORMAL
        )
        smb.close(tree_id, fid)
        return True
    except Exception:
        return False


def walk_share(
    conn: SMBConnection,
    share: str,
    path: str = "",
    depth: int = 0,
    max_depth: int | None = None,
    max_subdirs: int | None = None,
):
    if max_depth is not None and depth > max_depth:
        return
    try:
        pattern = ntpath.join(path, "*") if path else "*"
        entries = conn.listPath(share, pattern)
    except Exception:
        return

    dir_count = 0
    for entry in entries:
        name = entry.get_longname()
        if name in (".", ".."):
            continue
        full = ntpath.join(path, name) if path else name
        is_dir = entry.is_directory()
        if is_dir:
            if max_subdirs is not None and dir_count >= max_subdirs:
                continue
            dir_count += 1
        yield full, is_dir
        if is_dir:
            yield from walk_share(conn, share, full, depth + 1, max_depth, max_subdirs)


class ConnPool:
    def __init__(self, args: argparse.Namespace, size: int):
        self._q: queue.Queue[SMBConnection] = queue.Queue()
        self._size = 0
        for _ in range(size):
            conn = connect_smb(args)
            if conn:
                self._q.put(conn)
                self._size += 1

    def size(self) -> int:
        return self._size

    @contextmanager
    def acquire(self):
        conn = self._q.get()
        try:
            yield conn
        finally:
            self._q.put(conn)


def _check_path(
    pool: ConnPool,
    share: str,
    path: str,
    is_dir: bool,
    user_sids: frozenset[str],
    no_filter: bool,
    write_only: bool,
    do_test_write: bool,
) -> tuple[str, bool, list[dict], bool | None] | None:
    with pool.acquire() as conn:
        raw = get_acl(conn, share, path, is_dir)
        if raw is None:
            return None
        aces = parse_acl(raw, is_dir)
        if not aces:
            return None
        interesting: list[dict] = []
        for ace in aces:
            sid = ace["sid"]
            if sid in SKIP_SIDS or sid.split("-")[-1] in SKIP_DOMAIN_RIDS:
                continue
            if user_sids and not no_filter and sid not in user_sids:
                continue
            if write_only and not is_write_ace(ace):
                continue
            interesting.append(ace)
        if not interesting:
            return None
        write_confirmed: bool | None = None
        if do_test_write and is_dir and any(is_write_ace(a) for a in interesting):
            if test_write_access(conn, share, path):
                write_confirmed = True
            else:
                return None
        return path, is_dir, interesting, write_confirmed


def format_ace(ace: dict, resolved: str, is_write: bool, color: bool) -> str:
    perm_type = "Allowed" if ace["type"] == "ACCESS_ALLOWED_ACE" else "Denied "
    flags_str = " | ".join(ace["flags"])
    if color:
        name = bold(resolved, color)
        flags_str = red(flags_str, color) if is_write else flags_str
        return f"    {perm_type}: {name}  {flags_str}"
    return f"    {perm_type}: {resolved}  {flags_str}"


def run_spider(args):
    color = not args.no_color and not args.json

    conn = connect_smb(args)
    if conn is None:
        sys.exit(1)

    if not args.json:
        print(f"[+] Authenticated as {args.domain}\\{args.username} on {args.host}")

    pool = ConnPool(args, args.workers)
    if pool.size() == 0:
        print("[-] Failed to create worker connections", file=sys.stderr)
        sys.exit(1)

    resolver = SIDResolver(conn)

    user_sids: set[str] = set()
    if args.username and not args.no_filter:
        if not args.skip_samr:
            if not args.json:
                print("[*] Enumerating group memberships via SAMR ...")
            samr_sids = get_user_groups_samr(conn, args.domain or "", args.username, verbose=args.verbose)
            if samr_sids:
                user_sids.update(samr_sids)
                resolver.resolve_sids(set(samr_sids))
                if not args.json:
                    resolved_names = [resolver.get(s) for s in samr_sids]
                    print(f"[*] Current user groups ({len(samr_sids)}):")
                    for s, n in zip(samr_sids, resolved_names, strict=False):
                        print(f"    {n} ({s})")

        if args.groups:
            if not args.json:
                print(f"[*] Resolving {len(args.groups)} manually specified group(s) ...")
            name_to_sid = resolver.lookup_names(args.groups)
            for gname, gsid in name_to_sid.items():
                user_sids.add(gsid)
                resolver.cache[gsid] = gname
                if not args.json:
                    print(f"    {gname} -> {gsid}")
            if not args.json:
                for gname in args.groups:
                    if gname not in name_to_sid:
                        print(f"    [!] Could not resolve: {gname}")

    if args.shares:
        shares = args.shares
    else:
        if not args.json:
            print("[*] Enumerating shares ...")
        shares = list_shares(conn)
        if not shares:
            print("[-] No shares found or access denied", file=sys.stderr)
            sys.exit(1)
        if not args.all_shares:
            shares = [s for s in shares if not s.upper().endswith("$") or s.upper() in ("SYSVOL", "NETLOGON", "IPC$")]
            shares = [s for s in shares if s.upper() != "IPC$"]
        if not args.json:
            print(f"[*] Scanning {len(shares)} share(s): {', '.join(shares)}")

    found_any = False
    findings: list[dict] = []

    max_depth = args.depth or None
    max_subdirs = args.max_subdirs or None
    fs_user_sids = frozenset(user_sids)

    for share in shares:
        share_printed = False

        path_iter = itertools.chain(
            [("", True)],
            (
                (p, d)
                for p, d in walk_share(conn, share, max_depth=max_depth, max_subdirs=max_subdirs)
                if d or args.include_files
            ),
        )

        share_results: list[tuple[str, bool, list[dict], bool | None]] = []
        with ThreadPoolExecutor(max_workers=pool.size()) as executor:
            future_map: dict[Future[tuple[str, bool, list[dict], bool | None] | None], None] = {}
            for path, is_dir in path_iter:
                f = executor.submit(
                    _check_path,
                    pool,
                    share,
                    path,
                    is_dir,
                    fs_user_sids,
                    args.no_filter,
                    args.write_only,
                    args.test_write,
                )
                future_map[f] = None
            for f in as_completed(future_map):
                r = f.result()
                if r is not None:
                    share_results.append(r)

        share_results.sort(key=lambda r: r[0].lower())

        for path, _is_dir, raw_aces, write_confirmed in share_results:
            found_any = True
            display_path = f"\\\\{args.host}\\{share}\\{path}" if path else f"\\\\{args.host}\\{share}"
            resolver.resolve_sids({ace["sid"] for ace in raw_aces})
            interesting_aces = [(ace, resolver.get(ace["sid"]), is_write_ace(ace)) for ace in raw_aces]

            if args.json:
                entry: dict = {
                    "share": share,
                    "path": display_path,
                    "aces": [
                        {
                            "sid": ace["sid"],
                            "name": resolved,
                            "type": "allowed" if ace["type"] == "ACCESS_ALLOWED_ACE" else "denied",
                            "permissions": ace["flags"],
                            "write": iw,
                        }
                        for ace, resolved, iw in interesting_aces
                    ],
                }
                if args.test_write:
                    entry["write_confirmed"] = write_confirmed
                findings.append(entry)
            else:
                write_badge = f"  {green('[WRITE CONFIRMED]', color)}" if write_confirmed else ""
                if not share_printed:
                    print(f"\n{'=' * 60}")
                    print(f"  Share: {cyan(share, color)}")
                    print(f"{'=' * 60}")
                    share_printed = True
                print(f"\n  {bold(display_path, color)}{write_badge}")
                for ace, resolved, iw in interesting_aces:
                    print(format_ace(ace, resolved, iw, color))

    if args.json:
        print(json.dumps(findings, indent=2))
    elif not found_any:
        print("\n[-] No interesting ACLs found with current filters.")
        if user_sids:
            print("    Tip: try --no-filter to show all non-admin ACEs, or --write-only to focus on writes.")


def main():
    parser = argparse.ArgumentParser(
        description="Spider SMB shares and report directories with interesting ACLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect groups via SAMR, show write ACEs only
  aclspider 10.10.11.x -u alice -p 'P@ssw0rd' -d CORP --write-only

  # Specify groups manually (faster, no SAMR)
  aclspider 10.10.11.x -u alice -p 'P@ssw0rd' -d CORP --groups "IT Support" --skip-samr

  # Show all non-admin ACEs on SYSVOL (no user filter)
  aclspider 10.10.11.x -u alice -p 'P@ssw0rd' -d CORP -s SYSVOL --no-filter

  # Pass-the-hash
  aclspider 10.10.11.x -u alice -H aad3...:abc123... -d CORP
""",
    )

    parser.add_argument("host", help="Target SMB host (IP or hostname)")
    parser.add_argument("-u", "--username", default="", help="Username")
    parser.add_argument("-p", "--password", default="", help="Password")
    parser.add_argument("-d", "--domain", default="", help="Domain")
    parser.add_argument("-H", "--hashes", default="", metavar="LM:NT", help="NTLM hashes (LM:NT or :NT)")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    parser.add_argument("--aes-key", default="", help="AES key for Kerberos")
    parser.add_argument("--dc-ip", default=None, help="Domain controller IP (for Kerberos)")
    parser.add_argument("--ccache", default=None, help="Path to Kerberos ccache file")
    parser.add_argument("--port", default=445, type=int, help="SMB port (default: 445)")

    parser.add_argument("--workers", type=int, default=8, help="Parallel SMB connections for ACL checks (default: 8)")
    parser.add_argument("-s", "--shares", nargs="+", metavar="SHARE", help="Specific share(s) to scan")
    parser.add_argument("--all-shares", action="store_true", help="Include hidden/admin shares (ending in $)")
    parser.add_argument("--depth", type=int, default=3, help="Max recursion depth (default: 3, 0=unlimited)")
    parser.add_argument(
        "--max-subdirs",
        type=int,
        default=10,
        help="Max subdirs to enter per directory level (default: 10, 0=unlimited)",
    )
    parser.add_argument("--include-files", action="store_true", help="Also check ACLs on files (slow)")

    parser.add_argument(
        "--groups", nargs="+", metavar="NAME", help="Additional group names to include in filter (e.g. 'IT Support')"
    )
    parser.add_argument("--no-filter", action="store_true", help="Show all non-admin ACEs regardless of current user")
    parser.add_argument(
        "--skip-samr", action="store_true", help="Skip SAMR group enumeration (use --groups for manual input)"
    )
    parser.add_argument("--write-only", action="store_true", help="Only report ACEs that grant write-like permissions")
    parser.add_argument(
        "--test-write",
        action="store_true",
        help="Empirically test write access by creating+deleting a temp file (confirms share-level blocks)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON (suppresses all other output)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    run_spider(args)


if __name__ == "__main__":
    main()
