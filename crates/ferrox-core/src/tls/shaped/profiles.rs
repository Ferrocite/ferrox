// The pinned uTLS shapes, GREASE as the 0x0a0a sentinel; generated, never hand-edited.
use super::{Body, Ext, Profile};

static P_360: Profile = Profile {
    name: "360",
    ciphers: &[
        0xc00a, 0xc014, 0x0039, 0x006b, 0x0035, 0x003d, 0xc007, 0xc009, 0xc023, 0xc011, 0xc013,
        0xc027, 0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002f, 0x003c, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0017, 0x0018, 0x0019]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x3374,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x20, 0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32, 0x06, 0x73, 0x70, 0x64, 0x79,
                0x2f, 0x33, 0x08, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x2e, 0x31, 0x08, 0x68, 0x74,
                0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x754f,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0402, 0x0202,
            ]),
        },
    ],
};

static P_ANDROID: Profile = Profile {
    name: "android",
    ciphers: &[
        0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
        0x0035,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ]),
        },
    ],
};

pub(crate) static P_CHROME: Profile = Profile {
    name: "chrome",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: true,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x11ec, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x11ec, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x44cd,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0xfe0d,
            body: Body::Ech {
                suites: &[0x0001_0001],
                payloads: &[128, 160, 192, 224],
            },
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
    ],
};

static P_EDGE: Profile = Profile {
    name: "edge",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_FIREFOX: Profile = Profile {
    name: "firefox",
    ciphers: &[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x0022,
            body: Body::Raw(&[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x11ec, 0x001d, 0x0017],
                reuse: true,
            },
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0304, 0x0303]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x001c,
            body: Body::Raw(&[0x40, 0x01]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]),
        },
        Ext {
            kind: 0xfe0d,
            body: Body::Ech {
                suites: &[0x0001_0001, 0x0001_0003],
                payloads: &[223],
            },
        },
    ],
};

static P_HELLO360_11_0: Profile = Profile {
    name: "hello360_11_0",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x7550,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOCHROME_100: Profile = Profile {
    name: "hellochrome_100",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x4469,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOCHROME_100_PSK: Profile = Profile {
    name: "hellochrome_100_psk",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x4469,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
    ],
};

static P_HELLOCHROME_106_SHUFFLE: Profile = Profile {
    name: "hellochrome_106_shuffle",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: true,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x4469,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOCHROME_112_PSK_SHUF: Profile = Profile {
    name: "hellochrome_112_psk_shuf",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: true,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x4469,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
    ],
};

static P_HELLOCHROME_115_PQ: Profile = Profile {
    name: "hellochrome_115_pq",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: true,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x6399, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x6399, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x4469,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOCHROME_115_PQ_PSK: Profile = Profile {
    name: "hellochrome_115_pq_psk",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: true,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x6399, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x6399, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x4469,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
    ],
};

static P_HELLOCHROME_120: Profile = Profile {
    name: "hellochrome_120",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: true,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x4469,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0xfe0d,
            body: Body::Ech {
                suites: &[0x0001_0001],
                payloads: &[128, 160, 192, 224],
            },
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOCHROME_120_PQ: Profile = Profile {
    name: "hellochrome_120_pq",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: true,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x6399, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x6399, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x4469,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0xfe0d,
            body: Body::Ech {
                suites: &[0x0001_0001],
                payloads: &[128, 160, 192, 224],
            },
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
    ],
};

static P_HELLOCHROME_131: Profile = Profile {
    name: "hellochrome_131",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: true,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x11ec, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x11ec, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x4469,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0xfe0d,
            body: Body::Ech {
                suites: &[0x0001_0001],
                payloads: &[128, 160, 192, 224],
            },
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
    ],
};

static P_HELLOCHROME_58: Profile = Profile {
    name: "hellochrome_58",
    ciphers: &[
        0x0a0a, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
        0x002f, 0x0035, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x7550,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOCHROME_70: Profile = Profile {
    name: "hellochrome_70",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x7550,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOCHROME_72: Profile = Profile {
    name: "hellochrome_72",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOCHROME_96: Profile = Profile {
    name: "hellochrome_96",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x02]),
        },
        Ext {
            kind: 0x4469,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOFIREFOX_102: Profile = Profile {
    name: "hellofirefox_102",
    ciphers: &[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x0022,
            body: Body::Raw(&[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x001d, 0x0017],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0304, 0x0303]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x001c,
            body: Body::Raw(&[0x40, 0x01]),
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOFIREFOX_105: Profile = Profile {
    name: "hellofirefox_105",
    ciphers: &[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x0022,
            body: Body::Raw(&[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x001d, 0x0017],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0304, 0x0303]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x001c,
            body: Body::Raw(&[0x40, 0x01]),
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOFIREFOX_120: Profile = Profile {
    name: "hellofirefox_120",
    ciphers: &[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x0022,
            body: Body::Raw(&[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x001d, 0x0017],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0304, 0x0303]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x001c,
            body: Body::Raw(&[0x40, 0x01]),
        },
        Ext {
            kind: 0xfe0d,
            body: Body::Ech {
                suites: &[0x0001_0001, 0x0001_0003],
                payloads: &[223],
            },
        },
    ],
};

static P_HELLOFIREFOX_55: Profile = Profile {
    name: "hellofirefox_55",
    ciphers: &[
        0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x0033,
        0x0039, 0x002f, 0x0035, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018, 0x0019]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOFIREFOX_63: Profile = Profile {
    name: "hellofirefox_63",
    ciphers: &[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x0033, 0x0039, 0x002f, 0x0035, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x001d, 0x0017],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0304, 0x0303, 0x0302, 0x0301]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x001c,
            body: Body::Raw(&[0x40, 0x01]),
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOFIREFOX_99: Profile = Profile {
    name: "hellofirefox_99",
    ciphers: &[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x0022,
            body: Body::Raw(&[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x001d, 0x0017],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0304, 0x0303, 0x0302, 0x0301]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x001c,
            body: Body::Raw(&[0x40, 0x01]),
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOIOS_11_1: Profile = Profile {
    name: "helloios_11_1",
    ciphers: &[
        0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xcca9, 0xc030, 0xc02f, 0xc028, 0xc027,
        0xc014, 0xc013, 0xcca8, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x3374,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x2e, 0x02, 0x68, 0x32, 0x05, 0x68, 0x32, 0x2d, 0x31, 0x36, 0x05, 0x68, 0x32,
                0x2d, 0x31, 0x35, 0x05, 0x68, 0x32, 0x2d, 0x31, 0x34, 0x08, 0x73, 0x70, 0x64, 0x79,
                0x2f, 0x33, 0x2e, 0x31, 0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x08, 0x68, 0x74,
                0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018, 0x0019]),
        },
    ],
};

static P_HELLOIOS_12_1: Profile = Profile {
    name: "helloios_12_1",
    ciphers: &[
        0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xcca9, 0xc030, 0xc02f, 0xc028, 0xc027,
        0xc014, 0xc013, 0xcca8, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0xc008, 0xc012,
        0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x3374,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x2e, 0x02, 0x68, 0x32, 0x05, 0x68, 0x32, 0x2d, 0x31, 0x36, 0x05, 0x68, 0x32,
                0x2d, 0x31, 0x35, 0x05, 0x68, 0x32, 0x2d, 0x31, 0x34, 0x08, 0x73, 0x70, 0x64, 0x79,
                0x2f, 0x33, 0x2e, 0x31, 0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x08, 0x68, 0x74,
                0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018, 0x0019]),
        },
    ],
};

static P_HELLOIOS_13: Profile = Profile {
    name: "helloios_13",
    ciphers: &[
        0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xcca9, 0xc030,
        0xc02f, 0xc028, 0xc027, 0xc014, 0xc013, 0xcca8, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035,
        0x002f, 0xc008, 0xc012, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0304, 0x0303, 0x0302, 0x0301]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018, 0x0019]),
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOIOS_14: Profile = Profile {
    name: "helloios_14",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024,
        0xc023, 0xc00a, 0xc009, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c,
        0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018, 0x0019]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOSAFARI_16_0: Profile = Profile {
    name: "hellosafari_16_0",
    ciphers: &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a,
        0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x001d, 0x0017, 0x0018, 0x0019]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601,
                0x0201,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x01]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0015,
            body: Body::Pad,
        },
    ],
};

static P_HELLOSAFARI_26_3: Profile = Profile {
    name: "hellosafari_26_3",
    ciphers: &[
        0x0a0a, 0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a,
        0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
    ],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x0a0a, 0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
            ]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x0a0a, 0x11ec, 0x001d],
                reuse: false,
            },
        },
        Ext {
            kind: 0x002d,
            body: Body::Raw(&[0x01, 0x01]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0a0a, 0x0304, 0x0303]),
        },
        Ext {
            kind: 0x001b,
            body: Body::Raw(&[0x02, 0x00, 0x01]),
        },
        Ext {
            kind: 0x0a0a,
            body: Body::Grease,
        },
    ],
};

pub(crate) fn profile(name: &str) -> Option<&'static Profile> {
    let p = match name {
        "360" | "hello360_7_5" | "hello360_auto" => &P_360,
        "android" | "helloandroid_11_okhttp" => &P_ANDROID,
        "chrome" | "hellochrome_133" | "hellochrome_auto" => &P_CHROME,
        "edge" | "hellochrome_83" | "hellochrome_87" | "helloedge_85" | "helloedge_auto" => &P_EDGE,
        "firefox" | "hellofirefox_148" | "hellofirefox_auto" => &P_FIREFOX,
        "hello360_11_0" => &P_HELLO360_11_0,
        "hellochrome_100" | "hellochrome_102" | "helloedge_106" => &P_HELLOCHROME_100,
        "hellochrome_100_psk" => &P_HELLOCHROME_100_PSK,
        "hellochrome_106_shuffle" | "hellochrome_114_padding_psk_shuf" => {
            &P_HELLOCHROME_106_SHUFFLE
        }
        "hellochrome_112_psk_shuf" => &P_HELLOCHROME_112_PSK_SHUF,
        "hellochrome_115_pq" => &P_HELLOCHROME_115_PQ,
        "hellochrome_115_pq_psk" => &P_HELLOCHROME_115_PQ_PSK,
        "hellochrome_120" => &P_HELLOCHROME_120,
        "hellochrome_120_pq" => &P_HELLOCHROME_120_PQ,
        "hellochrome_131" => &P_HELLOCHROME_131,
        "hellochrome_58" | "hellochrome_62" => &P_HELLOCHROME_58,
        "hellochrome_70" => &P_HELLOCHROME_70,
        "hellochrome_72" => &P_HELLOCHROME_72,
        "hellochrome_96" | "helloqq_11_1" | "helloqq_auto" | "qq" => &P_HELLOCHROME_96,
        "hellofirefox_102" => &P_HELLOFIREFOX_102,
        "hellofirefox_105" => &P_HELLOFIREFOX_105,
        "hellofirefox_120" => &P_HELLOFIREFOX_120,
        "hellofirefox_55" | "hellofirefox_56" => &P_HELLOFIREFOX_55,
        "hellofirefox_63" | "hellofirefox_65" => &P_HELLOFIREFOX_63,
        "hellofirefox_99" => &P_HELLOFIREFOX_99,
        "helloios_11_1" => &P_HELLOIOS_11_1,
        "helloios_12_1" => &P_HELLOIOS_12_1,
        "helloios_13" => &P_HELLOIOS_13,
        "helloios_14" | "helloios_auto" | "ios" => &P_HELLOIOS_14,
        "hellosafari_16_0" => &P_HELLOSAFARI_16_0,
        "hellosafari_26_3" | "hellosafari_auto" | "safari" => &P_HELLOSAFARI_26_3,
        _ => return None,
    };
    Some(p)
}
