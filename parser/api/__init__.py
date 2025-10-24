from importlib import import_module
for _m in [
    "attribute_pb2", "capability_pb2", "common_pb2",
    "extcom_pb2", "nlri_pb2", "gobgp_pb2", "gobgp_pb2_grpc"
]:
    try:
        globals()[_m] = import_module(f"{__name__}.{_m}")
    except Exception:
        pass