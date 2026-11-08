//! Built-in SZU campus SSO & academic library database shortcuts and nested host extractor.
//!
//! Models all verified direct-jump shortcuts for the SZU Zero-Trust Workbench:
//! - Intelligent Finance Platform CAS `checkTicket` direct SSO
//! - SZU Library institutional logins: CNKI, HeinOnline, Oxford Scholarship,
//!   Cambridge Core, PKULaw (EZproxy), Web of Science (accproxy), and Westlaw (CARSI).

/// Collapsible category section in the right-hand Campus Services pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShortcutCategory {
    /// Campus administration, financial services, intranet, and office systems.
    CampusAffairs,
    /// Chinese and international institutional academic databases.
    AcademicDatabases,
    /// Teaching, research, or user-added custom shortcuts.
    Custom,
}

impl ShortcutCategory {
    /// Ordered list of all collapsible categories displayed in the Workbench.
    pub const ALL: [Self; 3] = [Self::CampusAffairs, Self::AcademicDatabases, Self::Custom];

    /// Localized display header for the collapsible category section.
    #[must_use]
    pub const fn title(self, english: bool) -> &'static str {
        match (self, english) {
            (Self::CampusAffairs, false) => "校园事务与办公",
            (Self::CampusAffairs, true) => "Campus & Administration",
            (Self::AcademicDatabases, false) => "中外文学术数据库",
            (Self::AcademicDatabases, true) => "Academic Databases",
            (Self::Custom, false) => "教务科研与自定义入口",
            (Self::Custom, true) => "Research & Custom Services",
        }
    }
}

/// Direct-jump campus service or academic database shortcut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampusShortcut {
    /// Stable identifier (`"szu-finance-sso"`, `"szu-heinonline"`, etc.).
    pub id: String,
    /// Display title in the Workbench favorites bar.
    pub name: String,
    /// Concise verification subtitle.
    pub subtitle: String,
    /// Direct SSO or proxy entry URL.
    pub url: String,
    /// Collapsible section category.
    pub category: ShortcutCategory,
    /// Whether pinned to the primary Workbench favorites grid.
    pub is_favorite: bool,
    /// Whether shipped as a built-in SZU shortcut.
    pub is_built_in: bool,
}

/// Direct CAS SSO ticket-exchange URL for the SZU Intelligent Finance Platform.
pub const FINANCE_CAS_SSO_URL: &str =
    "https://authserver.szu.edu.cn/authserver/login?service=http%3A%2F%2Fcwpt.szu.edu.cn%3A6090%2Fapi%2Flogcas%2FcheckTicket";

/// Direct SZU Online Self-Service Reimbursement System (深圳大学网上自助报账系统) URL.
pub const REIMBURSEMENT_SYSTEM_URL: &str = "http://172.31.134.31/wsyy/frame_container.aspx";

/// Direct SZU Library -> CNKI Shibboleth institutional SSO URL.
pub const CNKI_SZU_URL: &str =
    "https://fsso.cnki.net/Shibboleth.sso/Login?entityID=https://idp.szu.edu.cn/idp/shibboleth&target=https://fsso.cnki.net/secure/default.aspx";

/// Direct SZU Library -> HeinOnline WAYFless institutional SSO URL.
pub const HEINONLINE_SZU_URL: &str =
    "https://heinonline.org/HOL/WAYFless?entityID=https://idp.szu.edu.cn/idp/shibboleth&target=https://heinonline.org/HOL/Welcome";

/// Direct SZU Library -> Oxford Scholarship Online Shibboleth institutional SSO URL.
pub const OXFORD_SCHOLARSHIP_SZU_URL: &str =
    "https://oup-sp.sams-sigma.com/Shibboleth.sso/Login?entityID=https://idp.szu.edu.cn/idp/shibboleth&target=https%3A%2F%2Foup-sp.sams-sigma.com/shib%3Fdest=https%3A%2F%2Facademic.oup.com%2FSHIBBOLETH?dest=%2Fbooks";

/// Direct SZU Library -> Cambridge Core institutional SSO URL.
pub const CAMBRIDGE_CORE_SZU_URL: &str = "https://www.cambridge.org/core/idp/SZU_93544";

/// Direct SZU Library -> PKULaw (北大法宝) EZproxy institutional URL.
pub const PKULAW_SZU_URL: &str = "http://ezproxy.lib.szu.edu.cn/login?url=https://www.pkulaw.com/";

/// Direct SZU Library -> Web of Science Core Collection dedicated proxy URL.
pub const WOS_SZU_URL: &str =
    "http://accproxy.lib.szu.edu.cn/login?url=https://www.webofscience.com/wos/woscc/basic-search";

/// Direct SZU Library -> Thomson Reuters Westlaw CARSI federation URL.
pub const WESTLAW_SZU_URL: &str =
    "https://signon.thomsonreuters.com/federation/CARSI?entityid=https://idp.szu.edu.cn/idp/shibboleth&returnto=https://www.westlaw.com";

/// Returns the default SZU Workbench shortcuts including Finance SSO and all 7 academic databases.
///
/// # Examples
/// ```
/// use szu_securelink_rs::shortcuts::default_shortcuts;
/// let list = default_shortcuts();
/// assert!(list.iter().any(|s| s.id == "szu-finance-sso" && s.is_favorite));
/// assert!(list.iter().any(|s| s.id == "szu-heinonline" && s.is_favorite));
/// assert!(list.iter().any(|s| s.id == "szu-wos" && s.is_favorite));
/// ```
#[must_use]
pub fn default_shortcuts() -> Vec<CampusShortcut> {
    use ShortcutCategory::{AcademicDatabases, CampusAffairs};
    let entries = [
        ("szu-finance-sso", "财务服务大厅", "CAS 免登直达智慧财务综合服务平台", FINANCE_CAS_SSO_URL, CampusAffairs, true),
        ("szu-reimburse-system", "网上报账系统", "深圳大学网上自助报账系统（我的票夹/日常与差旅报销）", REIMBURSEMENT_SYSTEM_URL, CampusAffairs, true),
        ("szu-ehall", "办事大厅（一网通办）", "网上办事大厅 ehall.szu.edu.cn", "https://ehall.szu.edu.cn/new/index.html", CampusAffairs, true),
        ("szu-intranet", "内部网（公文通）", "深圳大学内部网与校园公文通", "https://www1.szu.edu.cn/", CampusAffairs, true),
        ("szu-oa", "OA 系统", "深圳大学协同办公系统", "http://210.39.3.155:9090/goLogin.do", CampusAffairs, true),
        ("szu-library", "深大图书馆", "深圳大学图书馆与数据库导航", "http://www.lib.szu.edu.cn/", CampusAffairs, true),
        ("szu-cnki-sso", "中国知网（深大机构登录）", "深大图书馆知网总库机构直达", CNKI_SZU_URL, AcademicDatabases, true),
        ("szu-pkulaw", "北大法宝", "深大图书馆 EZproxy 机构直达", PKULAW_SZU_URL, AcademicDatabases, true),
        ("szu-heinonline", "HeinOnline", "深大法学期刊与判例库机构直达", HEINONLINE_SZU_URL, AcademicDatabases, true),
        ("szu-oxford-scholarship", "Oxford Scholarship", "牛津学术专著电子书深大机构直达", OXFORD_SCHOLARSHIP_SZU_URL, AcademicDatabases, true),
        ("szu-cambridge", "剑桥数据库（Cambridge Core）", "剑桥期刊与电子书深大机构直达", CAMBRIDGE_CORE_SZU_URL, AcademicDatabases, true),
        ("szu-wos", "Web of Science", "SCIE/SSCI 核心合集深大专道直达", WOS_SZU_URL, AcademicDatabases, true),
        ("szu-westlaw", "Westlaw", "Thomson Reuters Westlaw 深大机构直达", WESTLAW_SZU_URL, AcademicDatabases, true),
    ];
    entries
        .into_iter()
        .map(|(id, name, subtitle, url, category, is_favorite)| CampusShortcut {
            id: id.to_string(),
            name: name.to_string(),
            subtitle: subtitle.to_string(),
            url: url.to_string(),
            category,
            is_favorite,
            is_built_in: true,
        })
        .collect()
}

/// Validates that `text` is a well-bounded `http://` or `https://` URL (`<= 2048` printable ASCII bytes).
#[must_use]
pub fn valid_url(text: &str) -> bool {
    if text.is_empty() || text.len() > 2048 || !text.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return false;
    }
    let rest = if let Some(r) = text.strip_prefix("https://") {
        r
    } else if let Some(r) = text.strip_prefix("http://") {
        r
    } else {
        return false;
    };
    let Some(host_port) = rest.split(['/', '?', '#']).next() else {
        return false;
    };
    let Some(host) = host_port.split(':').next() else {
        return false;
    };
    !host.is_empty()
        && host.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric() || b == b'[')
        && host_port
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push(((hi << 4) | lo) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn extract_host_only(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.split(':').next()?.to_ascii_lowercase();
    if !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        Some(host)
    } else {
        None
    }
}

/// Extracts distinct hostnames from shortcut URLs, including nested `service=`, `url=`,
/// `entityID=`, `target=`, and `returnto=` query parameters.
///
/// # Examples
/// ```
/// use szu_securelink_rs::shortcuts::{default_shortcuts, extract_hosts};
/// let hosts = extract_hosts(&default_shortcuts());
/// assert!(hosts.contains(&"cwpt.szu.edu.cn".to_string()));
/// assert!(hosts.contains(&"idp.szu.edu.cn".to_string()));
/// assert!(hosts.contains(&"accproxy.lib.szu.edu.cn".to_string()));
/// ```
#[must_use]
pub fn extract_hosts(shortcuts: &[CampusShortcut]) -> Vec<String> {
    let mut hosts = Vec::new();
    let mut push_unique = |candidate: Option<String>| {
        if let Some(h) = candidate
            && !hosts.contains(&h)
        {
            hosts.push(h);
        }
    };
    for item in shortcuts {
        push_unique(extract_host_only(&item.url));
        if let Some((_, query)) = item.url.split_once('?') {
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=')
                    && matches!(
                        k.to_ascii_lowercase().as_str(),
                        "service" | "url" | "entityid" | "target" | "returnto"
                    )
                {
                    let decoded = percent_decode(v);
                    push_unique(extract_host_only(&decoded));
                }
            }
        }
    }
    hosts
}
