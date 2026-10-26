#!/usr/bin/env python3
"""Restore the ML-KEM key share the pinned sing-box strips from REALITY handshakes.

xray-core at its pin refuses a REALITY ClientHello without X25519MLKEM768, so the
stock build answers with the cover certificate and the matrix records a TLS failure
instead of a measurement. Removing the filter leaves the same hello sing-box sends
for every other TLS server and works against both servers the matrix runs.
"""

import pathlib
import sys

FILTER = '''\tfor _, extension := range uConn.Extensions {
\t\tif ce, ok := extension.(*utls.SupportedCurvesExtension); ok {
\t\t\tce.Curves = common.Filter(ce.Curves, func(curveID utls.CurveID) bool {
\t\t\t\treturn curveID != utls.X25519MLKEM768
\t\t\t})
\t\t}
\t\tif ks, ok := extension.(*utls.KeyShareExtension); ok {
\t\t\tks.KeyShares = common.Filter(ks.KeyShares, func(share utls.KeyShare) bool {
\t\t\t\treturn share.Group != utls.X25519MLKEM768
\t\t\t})
\t\t}
\t}
\terr = uConn.BuildHandshakeState()
\tif err != nil {
\t\treturn nil, err
\t}

'''


def patch(root: pathlib.Path) -> None:
    path = root / "common/tls/reality_client.go"
    text = path.read_text()
    if FILTER not in text:
        if "X25519MLKEM768" in text:
            raise SystemExit(f"{path}: REALITY ML-KEM filter moved; update the patch")
        return
    text = text.replace(FILTER, "", 1)
    if "common." not in text:
        text = text.replace('\t"github.com/sagernet/sing/common"\n', "", 1)
    path.write_text(text)


if __name__ == "__main__":
    patch(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "upstream/sing-box"))
