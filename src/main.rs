use clap::Parser;
use rscert::Result;

const AFTER_HELP: &str = "\
EXAMPLES:
    $ rscert -install
    Install the local CA in the system trust store.

    $ rscert example.org
    Generate \"example.org.pem\" and \"example.org-key.pem\".

    $ rscert example.com myapp.dev localhost 127.0.0.1 ::1
    Generate \"example.com+4.pem\" and \"example.com+4-key.pem\".

    $ rscert \"*.example.it\"
    Generate \"_wildcard.example.it.pem\" and \"_wildcard.example.it-key.pem\".

    $ rscert -uninstall
    Uninstall the local CA (but do not delete it).

ENVIRONMENT:
    CAROOT
        Set the CA certificate and key storage location. (This allows
        maintaining multiple local CAs in parallel.)

    TRUST_STORES
        A comma-separated list of trust stores to install the local
        root CA into. Options are: \"system\", \"java\" and \"nss\" (includes
        Firefox). Autodetected by default.
";

#[derive(Parser, Debug)]
#[command(name = "rscert")]
#[command(version)]
#[command(about = "A simple zero-config tool to make locally-trusted development certificates")]
#[command(after_help = AFTER_HELP)]
struct Cli {
    /// Install the local CA in the system trust store
    #[arg(long)]
    install: bool,

    /// Uninstall the local CA from the system trust store
    #[arg(long)]
    uninstall: bool,

    /// Print the CA certificate and key storage location
    #[arg(long = "CAROOT")]
    caroot: bool,

    /// Customize the output certificate file path
    #[arg(long = "cert-file", value_name = "FILE")]
    cert_file: Option<String>,

    /// Customize the output key file path
    #[arg(long = "key-file", value_name = "FILE")]
    key_file: Option<String>,

    /// Customize the output PKCS#12 file path
    #[arg(long = "p12-file", value_name = "FILE")]
    p12_file: Option<String>,

    /// Generate a certificate for client authentication
    #[arg(long)]
    client: bool,

    /// Domain names or IP addresses to generate certificates for
    #[arg(value_name = "DOMAINS")]
    domains: Vec<String>,
}

fn main() -> Result<()> {
    let _cli = Cli::parse();
    println!("rscert - certificate generation tool");
    Ok(())
}
