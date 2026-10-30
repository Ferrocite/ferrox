//! The command line the release package documents. Parsing is deliberately
//! separate from doing: a bad invocation must refuse before a running lane is
//! touched, and it must say what is missing.

use std::process::exit;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Up,
    Serve,
    Down,
    Status,
    Ports,
    Tun,
    Login,
    Logout,
    Locations,
    Location,
    Version,
    Supervise,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outbound {
    Foxy,
    Veepn,
    Vless,
    Vmess,
    Trojan,
    Ss,
    Config,
}

#[derive(Debug)]
pub struct Options {
    pub action: Action,
    pub outbound: Option<Outbound>,
    pub config_file: String,
    pub vless: String,
    pub vmess: String,
    pub vmess_id: String,
    pub vmess_network: String,
    pub trojan: String,
    pub ss: String,
    pub ss_method: String,
    pub email: String,
    pub password: String,
    pub code: String,
    pub country: String,
    pub country_set: bool,
    pub city: String,
    pub city_set: bool,
    pub carrier: String,
    pub carrier_set: bool,
    pub upstream: String,
    pub exclude_domains: String,
    pub exclude_ports: String,
    pub region: String,
    pub veepn_domains: String,
    pub veepn_udid: String,
    pub fronts: String,
    pub fronts_set: bool,
    pub socks: u16,
    pub http: u16,
    pub mixed: u16,
    pub socks_set: bool,
    pub http_set: bool,
    pub mixed_set: bool,
    pub instance: Option<String>,
    pub all: bool,
    pub vpn: bool,
    pub browser: bool,
    pub debug: bool,
    pub ping: bool,
    pub loc_filter: String,
    pub loc_country: String,
    pub loc_city: String,
    pub supervise_pid: Option<u32>,
}

impl Default for Options {
    fn default() -> Self {
        let socks = env_port("FOXY_SOCKS_PORT", 10808);
        let http = env_port("FOXY_HTTP_PORT", 8080);
        let mixed = env_port("FOXY_MIXED_PORT", 10809);
        Self {
            action: Action::Up,
            outbound: None,
            config_file: String::new(),
            vless: String::new(),
            vmess: String::new(),
            vmess_id: String::new(),
            vmess_network: "tcp".to_owned(),
            trojan: String::new(),
            ss: String::new(),
            ss_method: "aes-256-gcm".to_owned(),
            email: String::new(),
            password: String::new(),
            code: String::new(),
            country: "US".to_owned(),
            country_set: false,
            city: String::new(),
            city_set: false,
            carrier: "auto".to_owned(),
            carrier_set: false,
            upstream: String::new(),
            exclude_domains: String::new(),
            exclude_ports: String::new(),
            region: String::new(),
            veepn_domains: String::new(),
            veepn_udid: String::new(),
            fronts: "socks,http,mixed".to_owned(),
            fronts_set: false,
            socks,
            http,
            mixed,
            socks_set: std::env::var_os("FOXY_SOCKS_PORT").is_some(),
            http_set: std::env::var_os("FOXY_HTTP_PORT").is_some(),
            mixed_set: std::env::var_os("FOXY_MIXED_PORT").is_some(),
            instance: None,
            all: false,
            vpn: false,
            browser: false,
            debug: false,
            ping: false,
            loc_filter: String::new(),
            loc_country: String::new(),
            loc_city: String::new(),
            supervise_pid: None,
        }
    }
}

fn env_port(name: &str, fallback: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

pub fn die(message: &str) -> ! {
    eprintln!("ferrox-cli: {message}");
    exit(1)
}

fn need<'a>(args: &'a [String], index: usize, flag: &str, hint: &str) -> &'a str {
    args.get(index + 1).map_or_else(
        || die(&format!("--{flag} wants {hint}; nothing was started.")),
        String::as_str,
    )
}

fn port(flag: &str, value: &str) -> u16 {
    match value.parse::<u16>() {
        Ok(port) if port != 0 => port,
        Ok(_) => die(&format!(
            "--{flag} wants a port between 1 and 65535, got '{value}'; nothing was started."
        )),
        Err(_) => die(&format!(
            "--{flag} wants a port number between 1 and 65535, got '{value}'; nothing was started."
        )),
    }
}

pub fn parse() -> Options {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut options = Options::default();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "up" => {
                options.action = Action::Up;
                index += 1;
            }
            "serve" => {
                options.action = Action::Serve;
                index += 1;
            }
            "down" => {
                options.action = Action::Down;
                index += 1;
            }
            "status" => {
                options.action = Action::Status;
                index += 1;
            }
            "ports" => {
                options.action = Action::Ports;
                index += 1;
            }
            "tun" => {
                options.action = Action::Tun;
                index += 1;
            }
            "login" => {
                options.action = Action::Login;
                index += 1;
            }
            "logout" => {
                options.action = Action::Logout;
                index += 1;
            }
            "locations" => {
                options.action = Action::Locations;
                index += 1;
                if index < args.len() && args[index] == "--ping" {
                    options.ping = true;
                    index += 1;
                }
                if index < args.len() && !args[index].starts_with('-') {
                    options.loc_filter = args[index].clone();
                    index += 1;
                }
            }
            "location" => {
                options.action = Action::Location;
                index += 1;
                if index < args.len() && !args[index].starts_with('-') {
                    options.loc_country = args[index].clone();
                    index += 1;
                }
                if index < args.len() && !args[index].starts_with('-') {
                    options.loc_city = args[index].clone();
                    index += 1;
                }
            }
            "version" => {
                options.action = Action::Version;
                index += 1;
            }
            "__supervise" => {
                options.action = Action::Supervise;
                index += 1;
                if index < args.len() {
                    options.supervise_pid = args[index].parse().ok();
                    index += 1;
                }
            }
            "--foxy" => {
                options.outbound = Some(Outbound::Foxy);
                index += 1;
            }
            "--veepn" => {
                options.outbound = Some(Outbound::Veepn);
                index += 1;
            }
            "--vless" => {
                options.outbound = Some(Outbound::Vless);
                options.vless = need(&args, index, "vless", "a vless:// share link").to_owned();
                index += 2;
            }
            "--vmess" => {
                options.outbound = Some(Outbound::Vmess);
                options.vmess = need(&args, index, "vmess", "HOST:PORT").to_owned();
                index += 2;
            }
            "--uuid" => {
                options.vmess_id = need(&args, index, "uuid", "the VMess user id").to_owned();
                index += 2;
            }
            "--network" => {
                options.vmess_network = need(&args, index, "network", "tcp or ws").to_owned();
                index += 2;
            }
            "--trojan" => {
                options.outbound = Some(Outbound::Trojan);
                options.trojan = need(&args, index, "trojan", "HOST:PORT").to_owned();
                index += 2;
            }
            "--ss" => {
                options.outbound = Some(Outbound::Ss);
                options.ss = need(&args, index, "ss", "HOST:PORT").to_owned();
                index += 2;
            }
            "--method" => {
                options.ss_method = need(&args, index, "method", "a shadowsocks method").to_owned();
                index += 2;
            }
            "--config" => {
                options.outbound = Some(Outbound::Config);
                options.config_file = need(&args, index, "config", "a JSON config path").to_owned();
                index += 2;
            }
            "--email" => {
                options.email = need(&args, index, "email", "an email address").to_owned();
                index += 2;
            }
            "--browser" => {
                options.browser = true;
                index += 1;
            }
            "--password" => {
                options.password = need(&args, index, "password", "a password").to_owned();
                index += 2;
            }
            "--code" => {
                options.code = need(&args, index, "code", "a two-factor code").to_owned();
                index += 2;
            }
            "--country" => {
                options.country = need(&args, index, "country", "a country code").to_owned();
                options.country_set = true;
                index += 2;
            }
            "--region" => {
                options.region = need(&args, index, "region", "a region id").to_owned();
                index += 2;
            }
            "--domains" => {
                options.veepn_domains =
                    need(&args, index, "domains", "comma-separated origins").to_owned();
                index += 2;
            }
            "--udid" => {
                options.veepn_udid = need(&args, index, "udid", "a device id").to_owned();
                index += 2;
            }
            "--city" => {
                options.city = need(&args, index, "city", "a city code").to_owned();
                options.city_set = true;
                index += 2;
            }
            "--carrier" => {
                let value = need(&args, index, "carrier", "auto, h1, h2 or h3");
                match value {
                    "auto" | "h1" | "h2" | "h3" => options.carrier = value.to_owned(),
                    _ => die(&format!(
                        "--carrier wants auto, h1, h2 or h3, got '{value}'; nothing was started."
                    )),
                }
                options.carrier_set = true;
                index += 2;
            }
            "--upstream" => {
                options.upstream =
                    need(&args, index, "upstream", "an http:// or socks5:// URL").to_owned();
                index += 2;
            }
            "--exclude-domains" => {
                options.exclude_domains = need(
                    &args,
                    index,
                    "exclude-domains",
                    "comma-separated domain suffixes",
                )
                .to_owned();
                index += 2;
            }
            "--exclude-ports" => {
                options.exclude_ports =
                    need(&args, index, "exclude-ports", "comma-separated ports").to_owned();
                index += 2;
            }
            "--fronts" => {
                options.fronts =
                    need(&args, index, "fronts", "a comma-separated front list").to_owned();
                options.fronts_set = true;
                index += 2;
            }
            "--socks" => {
                options.socks = port("socks", need(&args, index, "socks", "a port"));
                options.socks_set = true;
                index += 2;
            }
            "--http" => {
                options.http = port("http", need(&args, index, "http", "a port"));
                options.http_set = true;
                index += 2;
            }
            "--mixed" => {
                options.mixed = port("mixed", need(&args, index, "mixed", "a port"));
                options.mixed_set = true;
                index += 2;
            }
            "--instance" => {
                let value = need(
                    &args,
                    index,
                    "instance",
                    "a name of letters, digits, - or _",
                );
                if !value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    die(&format!(
                        "--instance wants letters, digits, - or _, got '{value}'; nothing was started."
                    ));
                }
                if value.len() > 32 {
                    die("an --instance name is at most 32 characters; nothing was started.");
                }
                options.instance = Some(value.to_owned());
                index += 2;
            }
            "--all" => {
                options.all = true;
                index += 1;
            }
            "--vpn" => {
                options.vpn = true;
                index += 1;
            }
            "--debug" => {
                options.debug = true;
                index += 1;
            }
            "--ping" => {
                options.ping = true;
                index += 1;
            }
            "--tun" => {
                options.action = Action::Tun;
                index += 1;
            }
            "-h" | "--help" => {
                usage();
            }
            "-V" | "--version" => {
                options.action = Action::Version;
                index += 1;
            }
            other => die(&format!("unknown argument: {other} (see --help)")),
        }
    }

    if options.ping && options.action != Action::Locations {
        die("--ping belongs to 'locations' (ferrox-cli locations --ping); nothing was started.");
    }
    if (!options.exclude_domains.is_empty() || !options.exclude_ports.is_empty())
        && options.outbound != Some(Outbound::Foxy)
    {
        die("--exclude-domains and --exclude-ports belong to the foxy lane; nothing was started.");
    }
    if options.all {
        if options.action != Action::Down {
            die("--all belongs to 'down' (ferrox-cli down --all); nothing was started.");
        }
        if options.instance.is_some() {
            die("--all stops every lane, so it takes no --instance; nothing was started.");
        }
    }
    if options.instance.is_some() && options.vpn {
        die(
            "the system proxy points at one lane: run the instance without --vpn and point the app at its fronts, or arm --vpn on the unnamed lane; nothing was started.",
        );
    }
    options
}

pub fn usage() -> ! {
    println!(
        "usage: ferrox-cli <command> [options]

commands
  login      save the foxy account once (prompts for the password; --browser
             signs in through a real browser instead)
  logout     stop the lane, then forget the account and its stored session
  locations  list the countries and cities the catalogue publishes
             (--ping measures the handshake to each edge, fastest first)
  location   remember an exit: location CC [CITY] (survives every up)
  up         start the lane in the background, print the port map (default)
  serve      start the lane in this terminal, until Ctrl-C
  down       stop the lane and clear the system proxy it set (--all: every lane)
  status     show the lane (--instance NAME for one of several), then its exit
  ports      print the port map and the settings to type
  tun        what TUN mode would need, and why this binary refuses it
  version    print the release binary's version

first run, then every run:
  ferrox-cli up --foxy --vpn
  ferrox-cli status
  ferrox-cli down

outbound (choose one)
  --foxy                 Foxy lane; account from the credentials file
  --veepn                VeePN lane; anonymous, no account and no server
  --vless LINK           a vless:// share link (tcp, ws, grpc, httpupgrade, xhttp)
  --vmess HOST:PORT --uuid ID
  --trojan HOST:PORT --password PW
  --ss HOST:PORT --method METHOD --password PW
  --config FILE          any JSON config this binary serves, used verbatim

foxy options
  --email ADDR           Firefox account, else FOXY_EMAIL, else the credentials file
  --password PW          password, else FOXY_PASS
  --browser              sign in through the system browser (no password sent here)
  --code CODE            two-factor code
  --country CC           exit country; default is the remembered one, else US
  --city CODE            city tier inside the country
  --carrier NAME         auto|h1|h2|h3, default auto
  --upstream URL         http:// or socks5(h):// hop to reach the edge through
  --exclude-domains LIST domain suffixes that leave the tunnel
  --exclude-ports LIST   destination ports that leave the tunnel

veepn options
  --region CC            exit region id, else the plane picks
  --domains URLS         comma-separated https origins to ask
  --udid ID              the device identity the plane sees

fronts
  --fronts LIST          socks,http,mixed (default all three)
  --socks PORT           default 10808
  --http PORT            default 8080
  --mixed PORT           default 10809
  --instance NAME        another lane beside the unnamed one
  --vpn                  point the Windows proxy at the fronts (unnamed lane only)
  --all                  with down: stop every lane
  --debug                keep the lane's dial trace in the log
  -h, --help             this text
  -V, --version          print the release binary's version"
    );
    exit(0)
}
