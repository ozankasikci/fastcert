//! fastcert - A simple zero-config tool to make locally-trusted development certificates.
//!
//! This is the command-line interface for fastcert, providing certificate generation
//! and CA management functionality. The main function parses command-line arguments
//! and dispatches to the appropriate modules for:
//! - CA installation and uninstallation
//! - Certificate generation for domains, IPs, emails, and URIs
//! - CSR-based certificate generation
//! - PKCS#12 bundle creation

use clap::Parser;
use fastcert::Result;

const AFTER_HELP: &str = "\
EXAMPLES:
    $ fastcert -install
    Install the local CA in the system trust store.

    $ fastcert example.org
    Generate \"example.org.pem\" and \"example.org-key.pem\".

    $ fastcert example.com myapp.dev localhost 127.0.0.1 ::1
    Generate \"example.com+4.pem\" and \"example.com+4-key.pem\".

    $ fastcert \"*.example.it\"
    Generate \"_wildcard.example.it.pem\" and \"_wildcard.example.it-key.pem\".

    $ fastcert -uninstall
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

/// Command-line interface structure.
///
/// Defines all command-line options and flags using clap's derive API.
/// The structure is parsed from command-line arguments and used to
/// determine which operations to perform.
#[derive(Parser, Debug)]
#[command(name = "fastcert")]
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

    /// Generate a certificate with an ECDSA key (default: RSA-2048)
    #[arg(long)]
    ecdsa: bool,

    /// Generate a PKCS#12 file (also known as .pfx) containing certificate and key
    #[arg(long)]
    pkcs12: bool,

    /// Generate a certificate based on the supplied CSR
    #[arg(long, value_name = "CSR")]
    csr: Option<String>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Enable debug output
    #[arg(long)]
    debug: bool,

    /// Suppress all output except errors
    #[arg(short, long)]
    quiet: bool,

    /// Domain names or IP addresses to generate certificates for
    #[arg(value_name = "DOMAINS")]
    domains: Vec<String>,
}

/// Main entry point for the fastcert command-line tool.
///
/// Parses command-line arguments and executes the requested operations:
/// - `-install`: Install the local CA to system trust stores
/// - `-uninstall`: Remove the local CA from system trust stores
/// - `-CAROOT`: Print the CA storage location
/// - `<domains...>`: Generate certificates for specified hosts
/// - `--csr <file>`: Generate certificate from a CSR
///
/// # Returns
///
/// `Ok(())` on success, or an error if any operation fails.
///
/// # Errors
///
/// Returns an error if:
/// - Invalid command-line arguments are provided
/// - CA operations fail
/// - Certificate generation fails
fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set verbose mode if requested
    if cli.verbose {
        unsafe {
            std::env::set_var("RSCERT_VERBOSE", "1");
        }
    }

    // Set debug mode if requested (implies verbose)
    if cli.debug {
        unsafe {
            std::env::set_var("RSCERT_DEBUG", "1");
            std::env::set_var("RSCERT_VERBOSE", "1");
        }
    }

    // Set quiet mode if requested (overrides verbose/debug)
    if cli.quiet {
        unsafe {
            std::env::set_var("RSCERT_QUIET", "1");
        }
    }

    // Handle -CAROOT flag
    if cli.caroot {
        if cli.install || cli.uninstall {
            eprintln!("ERROR: you can't set -install/-uninstall and -CAROOT at the same time");
            std::process::exit(1);
        }
        println!("{}", fastcert::ca::get_caroot()?);
        return Ok(());
    }

    // Handle conflicting flags
    if cli.install && cli.uninstall {
        eprintln!("ERROR: you can't set -install and -uninstall at the same time");
        std::process::exit(1);
    }

    // Handle CSR conflicts
    if cli.csr.is_some() {
        if cli.pkcs12 || cli.ecdsa || cli.client {
            eprintln!("ERROR: can only combine -csr with -install and -cert-file");
            std::process::exit(1);
        }
        if !cli.domains.is_empty() {
            eprintln!("ERROR: can't specify extra arguments when using -csr");
            std::process::exit(1);
        }
    }

    // If no arguments, show usage
    if !cli.install && !cli.uninstall && cli.domains.is_empty() && cli.csr.is_none() {
        Cli::parse_from(["fastcert", "--help"]);
        return Ok(());
    }

    // Handle -install mode
    if cli.install {
        fastcert::ca::install()?;
        if cli.domains.is_empty() && cli.csr.is_none() {
            return Ok(());
        }
    }

    // Handle -uninstall mode
    if cli.uninstall {
        fastcert::ca::uninstall()?;
        return Ok(());
    }

    // Handle CSR-based certificate generation
    if let Some(csr_path) = cli.csr {
        fastcert::cert::generate_from_csr(&csr_path, cli.cert_file.as_deref())?;
        return Ok(());
    }

    // Handle regular certificate generation
    if !cli.domains.is_empty() {
        fastcert::cert::generate_certificate(
            &cli.domains,
            cli.cert_file.as_deref(),
            cli.key_file.as_deref(),
            cli.p12_file.as_deref(),
            cli.client,
            cli.ecdsa,
            cli.pkcs12,
        )?;
    }

    Ok(())
}
