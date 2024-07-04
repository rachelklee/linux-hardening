//
// SV-16707r1_rule
pref("security.default_personal_cert", "Ask Every Time", locked);

// SV-16710r3_rule
pref("network.protocol-handler.external.shell", false, locked);

// SV-16711r2_rule
pref("plugin.disable_full_page_plugin_for_types", "PDF, FDF, XFDF, LSL, LSO, LSS, IQY, RQY, XLK, XLS, XLT, POT PPS, PPT, DOS, DOT, WKS, BAT, PS, EPS, WCH, WCM, WB1, WB3, RTF, DOC, MDB, MDE, WBK, WB1, WCH, WCM, AD, ADP", locked);

// SV-16713r1_rule
pref("browser.formfill.enable", false, locked);

// SV16714r1_rule
pref("signon.prefillForms", false, locked);

// SV-16715r2_rule
pref("signon.rememberSignons", false, locked);

// SV-16716r4_rule
pref("places.history.enabled", true, locked);

// SV-16717r1_rule
pref("dom.disable_window_open_feature.status", true, locked);

// SV-16718r1_rule // cannot load from this file, have to be done manually
pref("dom.disable_window_move_resize", true, locked);

// SV-16925r6_rule
pref("security.enable_tls", true, locked);
pref("security.tls.version.min", 2, locked);
pref("security.tls.version.max", 3, locked);

// SV-1927r1_rule // cannot load from this file, have to be done manually
pref("dom.disable_window_flip", true, locked);

// SV-16928r2_rule
pref("dom.event.contextmenu.enabled", false, locked);

// SV-16929r1_rule
pref("dom.disable_window_status_change", true, locked);

// SV-16930r1_rule
pref("dom.disable_window_open_feature.status", true, locked);

// SV-16931r1_rule
pref("security.warn_leaving_secure", true, locked);

// SV-21887r3_rule
pref("app.update.enabled", true, locked);

// SV-59603r1_rule
pref("extensions.update.enabled", false, locked);

// SV-21890r1_rule
pref("browser.search.update", false, locked);

// SV-79381r2_rule
pref("xpinstall.enabled", false, locked);

// SV-93759r1_rule
pref("datareporting.policy.dataSubmissionEnabled", false, locked);
