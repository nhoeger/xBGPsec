import json
import logging
import time
import ipaddress

import grpc
from google.protobuf.descriptor import FieldDescriptor as FD

from api import gobgp_pb2, gobgp_pb2_grpc, attribute_pb2, nlri_pb2, common_pb2
# from google.protobuf.any_pb2 import Any  # not used

from ris_live import RisLive  # NEW

# --- Configuration ---
GOBGP_API_HOST = 'localhost:50051'
RIPE_RIS_HOST = "ris-live.ripe.net"
# A client description is required by RIPE RIS
CLIENT_DESCRIPTION = "gobgp-feeder-v0.1"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def to_comm_val(communities):
    out = []
    for c in communities or []:
        if isinstance(c, str) and ':' in c:
            left, right = c.split(':', 1)
            try:
                out.append((int(left) << 16) + int(right))
            except Exception:
                continue
        elif isinstance(c, (list, tuple)) and len(c) == 2:
            try:
                out.append((int(c[0]) << 16) + int(c[1]))
            except Exception:
                continue
    return out

def family_for_prefix(prefix: str) -> common_pb2.Family:
    afi = common_pb2.Family.AFI_IP6 if ':' in prefix else common_pb2.Family.AFI_IP
    return common_pb2.Family(afi=afi, safi=common_pb2.Family.SAFI_UNICAST)
 
def _to_int(x):
    try:
        return int(x)
    except Exception:
        try:
            if isinstance(x, str) and x.upper().startswith("AS"):
                return int(x[2:])
        except Exception:
            pass
    return None

def normalize_as_path(path):
    """Flatten and convert a RIS path (list/str/nested) to a flat list[int]."""
    out = []
    if isinstance(path, str):
        s = path.replace('{', ' ').replace('}', ' ')
        for tok in s.split():
            v = _to_int(tok)
            if v is not None:
                out.append(v)
        return out
    if isinstance(path, (list, tuple)):
        for el in path:
            if isinstance(el, int):
                out.append(el)
            elif isinstance(el, str):
                v = _to_int(el)
                if v is not None:
                    out.append(v)
            elif isinstance(el, (list, tuple)):
                for sub in el:
                    v = _to_int(sub)
                    if v is not None:
                        out.append(v)
    return out

def sanitize_next_hop(nh):
    """
    RIS can send next_hop like "2001:db8::1,fe80::1". Return a single, valid, routable IP:
    - prefer non-link-local over link-local
    - accept string or list
    """
    if nh is None:
        return None
    cand = []
    if isinstance(nh, str):
        parts = [p.strip() for p in nh.split(',') if p.strip()]
        cand.extend(parts)
    elif isinstance(nh, (list, tuple)):
        cand.extend(nh)
    else:
        cand.append(str(nh))
    parsed = []
    for c in cand:
        try:
            ip = ipaddress.ip_address(c.split('%', 1)[0])  # drop zone if present
            parsed.append(ip)
        except ValueError:
            continue
    if not parsed:
        return None
    # prefer non-link-local
    for ip in parsed:
        if not (ip.version == 6 and ip.is_link_local):
            return str(ip)
    return str(parsed[0])

_nlri_wrap_func = None
def nlri_wrap_ip_prefix(ip_pfx: nlri_pb2.IPAddressPrefix) -> nlri_pb2.NLRI:
    """Wrap IPAddressPrefix into NLRI for whatever NLRI layout this proto uses."""
    global _nlri_wrap_func
    if _nlri_wrap_func:
        return _nlri_wrap_func(ip_pfx)
    desc = nlri_pb2.NLRI.DESCRIPTOR
    # Prefer: enum (type-like) + bytes (value-like)
    enum_field = next((f for f in desc.fields if f.type == FD.TYPE_ENUM), None)
    bytes_field = next((f for f in desc.fields if f.type == FD.TYPE_BYTES), None)
    if enum_field and bytes_field:
        enum = enum_field.enum_type
        # Try to find an enum that mentions "prefix"
        candidate = next((v for v in enum.values if "prefix" in v.name.lower()), None)
        enum_num = candidate.number if candidate else next((v.number for v in enum.values if v.number != 0), 0)
        def _wrap_enum_bytes(p: nlri_pb2.IPAddressPrefix):
            return nlri_pb2.NLRI(**{
                enum_field.name: enum_num,
                bytes_field.name: p.SerializeToString()
            })
        _nlri_wrap_func = _wrap_enum_bytes
        return _nlri_wrap_func(ip_pfx)
    # Fallback: direct message field carrying IPAddressPrefix (oneof style)
    msg_field = next((f for f in desc.fields
                      if f.message_type and f.message_type.full_name.endswith("IPAddressPrefix")), None)
    if msg_field:
        def _wrap_direct(p: nlri_pb2.IPAddressPrefix):
            return nlri_pb2.NLRI(**{msg_field.name: p})
        _nlri_wrap_func = _wrap_direct
        return _nlri_wrap_func(ip_pfx)
    # If nothing matched, raise a helpful error
    raise RuntimeError(f"Unsupported NLRI layout. Fields: {[f.name for f in desc.fields]}")

def create_gobgp_path(announcement):
    """Converts a RIPE RIS announcement into a GoBGP Path object."""
    prefix, length = announcement['prefix'].split('/')
    ip_pfx = nlri_pb2.IPAddressPrefix(prefix_len=int(length), prefix=prefix)
    nlri = nlri_wrap_ip_prefix(ip_pfx)

    attributes = []  # list[attribute_pb2.Attribute]

    # ORIGIN
    origin_attr = attribute_pb2.OriginAttribute(origin=0)  # IGP
    attributes.append(attribute_pb2.Attribute(origin=origin_attr))

    # AS_PATH
    if announcement.get('path'):
        nums = normalize_as_path(announcement['path'])
        if nums:
            as_path_attr = attribute_pb2.AsPathAttribute(
                segments=[attribute_pb2.AsSegment(numbers=nums)]
            )
            attributes.append(attribute_pb2.Attribute(as_path=as_path_attr))

    # NEXT_HOP
    nh = sanitize_next_hop(announcement.get('next_hop'))
    if nh:
        next_hop_attr = attribute_pb2.NextHopAttribute(next_hop=nh)
        attributes.append(attribute_pb2.Attribute(next_hop=next_hop_attr))

    # COMMUNITIES
    if announcement.get('communities'):
        communities_attr = attribute_pb2.CommunitiesAttribute(
            communities=to_comm_val(announcement['communities'])
        )
        attributes.append(attribute_pb2.Attribute(communities=communities_attr))

    # Ensure ASN is int
    src_asn = _to_int(announcement.get('peer_asn')) or 0

    path = gobgp_pb2.Path(
        nlri=nlri,
        pattrs=attributes,
        family=family_for_prefix(prefix),
        source_id=announcement.get('peer'),
        source_asn=src_asn,
    )
    return path

def main():
    """Main function to connect to RIPE RIS and forward to GoBGP."""
    
    # 1. Connect to GoBGP gRPC server
    try:
        channel = grpc.insecure_channel(GOBGP_API_HOST)
        # Try known stub class names
        stub_cls = None
        for name in ("GoBgpServiceStub", "GobgpApiStub", "GoBGPApiStub"):
            stub_cls = getattr(gobgp_pb2_grpc, name, None)
            if stub_cls:
                break
        if not stub_cls:
            available = [n for n in dir(gobgp_pb2_grpc) if n.endswith("Stub")]
            raise RuntimeError(f"No GoBGP stub found. Available: {available}")
        stub = stub_cls(channel)
        logger.info(f"Using gRPC stub {stub_cls.__name__}")

        # Optional health check if method exists
        if hasattr(stub, "GetNeighbor"):
            stub.GetNeighbor(gobgp_pb2.GetNeighborRequest(), timeout=5)
        logger.info(f"Connected to GoBGP at {GOBGP_API_HOST}")
    except grpc.RpcError as e:
        logger.error(f"Failed to connect to GoBGP at {GOBGP_API_HOST}: {e.details() if hasattr(e, 'details') else e}")
        logger.error("Please ensure GoBGP is running with the gRPC API enabled.")
        return

    # 2. Connect to RIPE RIS Live stream
    stream_params = {
        "host": RIPE_RIS_HOST,
        "client": CLIENT_DESCRIPTION,
    }
    stream = RisLive(stream_params)

    logger.info(f"Connecting to RIPE RIS Live at {RIPE_RIS_HOST}...")

    # 3. Process messages
    for msg in stream:
        try:
            obj = json.loads(msg.data)
        except Exception:
            continue

        t = obj.get('type')
        if t == 'ris_hello':
            logger.info("RIS hello received")
            continue
        if t == 'ris_subscribe_ok':
            logger.info("RIS subscription confirmed")
            continue
        if t == 'ris_error':
            logger.error(f"RIS error: {obj.get('data')}")
            continue

        # We are only interested in BGP Updates
        if t != 'ris_message':
            continue
        upd = obj.get('data') or {}
        if upd.get('type') != 'UPDATE':
            continue

        peer = upd.get('peer')
        peer_asn = _to_int(upd.get('peer_asn')) or 0
        as_path = normalize_as_path(upd.get('path') or [])
        communities = upd.get('community') or []

        # Handle Announcements
        if upd.get('announcements'):
            for announcement in upd['announcements']:
                for prefix in announcement.get('prefixes') or []:
                    logger.debug(f"Announcement: {prefix} from peer AS{peer_asn}")
                    try:
                        path = create_gobgp_path({
                            'prefix': prefix,
                            'path': as_path,
                            'next_hop': announcement.get('next_hop'),
                            'communities': communities,
                            'peer': peer,
                            'peer_asn': peer_asn,
                        })
                        stub.AddPath(gobgp_pb2.AddPathRequest(path=path))
                        logger.info(f"Added path for {prefix} from peer AS{peer_asn}")
                    except Exception as e:
                        logger.error(f"Error processing announcement: {e}")

        # Handle Withdrawals
        if upd.get('withdrawals'):
            for w in upd['withdrawals']:
                # withdrawals can be either a string prefix or an object with prefixes
                if isinstance(w, str):
                    prefixes = [w]
                    w_next_hop = None
                elif isinstance(w, dict):
                    prefixes = w.get('prefixes') or []
                    w_next_hop = w.get('next_hop')
                else:
                    continue
                for prefix in prefixes:
                    try:
                        ip, length = prefix.split('/')
                        ip_pfx = nlri_pb2.IPAddressPrefix(prefix_len=int(length), prefix=ip)
                        nlri = nlri_wrap_ip_prefix(ip_pfx)

                        nh = sanitize_next_hop(w_next_hop or upd.get('next_hop') or peer)
                        pattrs = []
                        if nh:
                            pattrs.append(attribute_pb2.Attribute(
                                next_hop=attribute_pb2.NextHopAttribute(next_hop=nh)
                            ))

                        path = gobgp_pb2.Path(
                            nlri=nlri,
                            pattrs=pattrs,
                            family=family_for_prefix(ip),
                            source_id=peer,
                            source_asn=peer_asn,
                        )
                        stub.DeletePath(gobgp_pb2.DeletePathRequest(path=path))
                        logger.info(f"Withdrew path for {prefix} from AS{peer_asn}")
                    except Exception as e:
                        logger.error(f"Error processing withdrawal: {e}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down.")
