use axum::{
    Router,
    routing::{get, post},
    Json, response::IntoResponse,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Mutex};
use tokio::net::TcpListener;
use once_cell::sync::Lazy;

// 使用全局变量存储规则
static RULES: Lazy<Mutex<Vec<Rule>>> = Lazy::new(|| Mutex::new(Vec::new()));

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Rule {
    rule_type: RuleType,
    value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainWildcard,
    DomainRegex,
    Geosite,
    IpCidr,
    IpCidr6,
    IpSuffix,
    IpAsn,
    Geoip,
    SrcGeoip,
    SrcIpAsn,
    SrcIpCidr,
    SrcIpSuffix,
    DstPort,
    SrcPort,
    InPort,
    InType,
    InUser,
    InName,
    ProcessPath,
    ProcessPathRegex,
    ProcessName,
    ProcessNameRegex,
    Uid,
    Network,
    Dscp,
    Match,
}

// 处理获取规则列表的请求
async fn get_rules() -> impl IntoResponse {
    let rules = RULES.lock().unwrap();
    
    // 将规则转换为文本格式
    let mut text = String::new();
    for rule in rules.iter() {
        text.push_str(&format!("{},{}\n", rule.rule_type.to_string(), rule.value));
    }
    
    text
}

// 处理添加新规则的请求
async fn add_rule(Json(rule): Json<Rule>) -> impl IntoResponse {
    RULES.lock().unwrap().push(rule);
    StatusCode::CREATED
}

impl std::fmt::Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RuleType::*;
        match self {
            Domain => write!(f, "DOMAIN"),
            DomainSuffix => write!(f, "DOMAIN-SUFFIX"),
            DomainKeyword => write!(f, "DOMAIN-KEYWORD"),
            DomainWildcard => write!(f, "DOMAIN-WILDCARD"),
            DomainRegex => write!(f, "DOMAIN-REGEX"),
            Geosite => write!(f, "GEOSITE"),
            IpCidr => write!(f, "IP-CIDR"),
            IpCidr6 => write!(f, "IP-CIDR6"),
            IpSuffix => write!(f, "IP-SUFFIX"),
            IpAsn => write!(f, "IP-ASN"),
            Geoip => write!(f, "GEOIP"),
            SrcGeoip => write!(f, "SRC-GEOIP"),
            SrcIpAsn => write!(f, "SRC-IP-ASN"),
            SrcIpCidr => write!(f, "SRC-IP-CIDR"),
            SrcIpSuffix => write!(f, "SRC-IP-SUFFIX"),
            DstPort => write!(f, "DST-PORT"),
            SrcPort => write!(f, "SRC-PORT"),
            InPort => write!(f, "IN-PORT"),
            InType => write!(f, "IN-TYPE"),
            InUser => write!(f, "IN-USER"),
            InName => write!(f, "IN-NAME"),
            ProcessPath => write!(f, "PROCESS-PATH"),
            ProcessPathRegex => write!(f, "PROCESS-PATH-REGEX"),
            ProcessName => write!(f, "PROCESS-NAME"),
            ProcessNameRegex => write!(f, "PROCESS-NAME-REGEX"),
            Uid => write!(f, "UID"),
            Network => write!(f, "NETWORK"),
            Dscp => write!(f, "DSCP"),
            Match => write!(f, "MATCH"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // gzip compression layer
    let compression_layer = tower_http::compression::CompressionLayer::new();

    let app = Router::new()
        .route("/rules", get(get_rules))
        .route("/rules", post(add_rule))
        .layer(compression_layer);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3500));
    let listener = TcpListener::bind(addr).await?;

    println!("Server running on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
