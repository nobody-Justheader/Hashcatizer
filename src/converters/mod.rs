pub mod ansible;
pub mod atmail;
pub mod bitcoin;
pub mod bitlocker;
pub mod bitwarden;
pub mod blockchain;
pub mod cisco;
pub mod dmg;
pub mod electrum;
pub mod encfs;
pub mod ethereum;
pub mod ios;
pub mod keepass;
pub mod lastpass;
pub mod ldif;
pub mod lion;
pub mod luks;
pub mod mac;
pub mod mongodb;
pub mod mozilla;
pub mod netntlm;
pub mod network;
pub mod office;
pub mod onepassword;
pub mod pcap;
pub mod pdf;
pub mod pgpdisk;
pub mod pgpsda;
pub mod pgpwde;
pub mod pwsafe;
pub mod sap;
pub mod sevenz;
pub mod signal;
pub mod ssh;
pub mod telegram;
pub mod truecrypt;
pub mod vdi;
pub mod veracrypt;
pub mod zed;
// batch
pub mod androidbackup;
pub mod androidfde;
pub mod axcrypt;
pub mod bestcrypt;
pub mod cardano;
pub mod coinomi;
pub mod dashlane;
pub mod deepsound;
pub mod diskcryptor;
pub mod dpapimk;
pub mod ecryptfs;
pub mod enpass;
pub mod fvde;
pub mod geli;
pub mod htdigest;
pub mod hccapx;
pub mod iwork;
pub mod keychain;
pub mod keyring;
pub mod known_hosts;
pub mod libreoffice;
pub mod monero;
pub mod multibit;
pub mod openbsd_softraid;
pub mod openssl_enc;
pub mod pem;
pub mod pfx;
pub mod restic;
pub mod staroffice;
pub mod strip;
pub mod tezos;
pub mod vmx;
// extended
pub mod aix;
pub mod andotp;
pub mod applenotes;
pub mod bks;
pub mod ccache;
pub mod ejabberd;
pub mod gitea;
pub mod ikescan;
pub mod kdcdump;
pub mod keystore_jks;
pub mod kirbi;
pub mod keplr;
pub mod kwallet;
pub mod krb;
pub mod lotus;
pub mod prosody;
pub mod radius;
pub mod sipdump;

/// Convert data/path using the named converter. Returns extracted hash lines.
pub fn run(name: &str, data: &[u8], path: &str) -> Option<Vec<String>> {
    use std::path::Path;
    let filename = path.to_string();
    let fpath = Path::new(path);
    match name {
        "ansible"        => ansible::convert(&data, &filename),
        "atmail"         => atmail::convert(&data, &filename),
        "bitcoin"        => bitcoin::convert(&data, &filename),
        "bitlocker"      => bitlocker::convert(&data, &filename),
        "bitwarden"      => bitwarden::convert(&data, &filename),
        "blockchain"     => blockchain::convert(&data, &filename),
        "cisco"          => cisco::convert(&data, &filename),
        "dmg"            => dmg::convert(&data, &filename),
        "electrum"       => electrum::convert(&data, &filename),
        "encfs"          => encfs::convert(&data, &filename),
        "ethereum"       => ethereum::convert(&data, &filename),
        "ios"            => ios::convert(fpath),
        "keepass"        => keepass::convert(&data, &filename),
        "lastpass"       => lastpass::convert(&data, &filename),
        "ldif"           => ldif::convert(&data, &filename),
        "lion"           => lion::convert(&data, &filename),
        "luks"           => luks::convert(&data, &filename),
        "mac"            => mac::convert(&data, &filename),
        "mongodb"        => mongodb::convert(&data, &filename),
        "mozilla"        => mozilla::convert(fpath),
        "netntlm"        => netntlm::convert(&data, &filename),
        "network"        => network::convert(&data, &filename),
        "office"         => office::convert(&data, &filename),
        "1password"      => onepassword::convert(fpath),
        "pcap"           => pcap::convert(&data, &filename),
        "pdf"            => pdf::convert(&data, &filename),
        "pgpdisk"        => pgpdisk::convert(&data, &filename),
        "pgpsda"         => pgpsda::convert(&data, &filename),
        "pgpwde"         => pgpwde::convert(&data, &filename),
        "pwsafe"         => pwsafe::convert(&data, &filename),
        "sap"            => sap::convert(&data, &filename),
        "7z"             => sevenz::convert(&data, &filename),
        "signal"         => signal::convert(fpath),
        "ssh"            => ssh::convert(&data, &filename),
        "telegram"       => telegram::convert(&data, &filename),
        "truecrypt"      => truecrypt::convert(&data, &filename),
        "vdi"            => vdi::convert(&data, &filename),
        "veracrypt"      => veracrypt::convert(&data, &filename),
        "zed"            => zed::convert(&data, &filename),
        // batch
        "androidbackup"  => androidbackup::convert(&data, &filename),
        "androidfde"     => androidfde::convert(&data, &filename),
        "axcrypt"        => axcrypt::convert(&data, &filename),
        "bestcrypt"      => bestcrypt::convert(&data, &filename),
        "cardano"        => cardano::convert(&data, &filename),
        "coinomi"        => coinomi::convert(&data, &filename),
        "dashlane"       => dashlane::convert(&data, &filename),
        "deepsound"      => deepsound::convert(&data, &filename),
        "diskcryptor"    => diskcryptor::convert(&data, &filename),
        "dpapimk"        => dpapimk::convert(&data, &filename),
        "ecryptfs"       => ecryptfs::convert(&data, &filename),
        "enpass"         => enpass::convert(&data, &filename),
        "fvde"           => fvde::convert(&data, &filename),
        "geli"           => geli::convert(&data, &filename),
        "htdigest"       => htdigest::convert(&data, &filename),
        "hccapx"         => hccapx::convert(&data, &filename),
        "iwork"          => iwork::convert(&data, &filename),
        "keychain"       => keychain::convert(&data, &filename),
        "keyring"        => keyring::convert(&data, &filename),
        "known_hosts"    => known_hosts::convert(&data, &filename),
        "libreoffice"    => libreoffice::convert(&data, &filename),
        "monero"         => monero::convert(&data, &filename),
        "multibit"       => multibit::convert(&data, &filename),
        "openbsd_softraid" => openbsd_softraid::convert(&data, &filename),
        "openssl"        => openssl_enc::convert(&data, &filename),
        "pem"            => pem::convert(&data, &filename),
        "pfx"            => pfx::convert(&data, &filename),
        "restic"         => restic::convert(&data, &filename),
        "staroffice"     => staroffice::convert(&data, &filename),
        "strip"          => strip::convert(&data, &filename),
        "tezos"          => tezos::convert(&data, &filename),
        "vmx"            => vmx::convert(&data, &filename),
        // extended
        "aix"            => aix::convert(&data, &filename),
        "andotp"         => andotp::convert(&data, &filename),
        "applenotes"     => applenotes::convert(data, &filename),
        "bks"            => bks::convert(&data, &filename),
        "ccache"         => ccache::convert(&data, &filename),
        "ejabberd"       => ejabberd::convert(&data, &filename),
        "gitea"          => gitea::convert(&data, &filename),
        "ikescan"        => ikescan::convert(&data, &filename),
        "kdcdump"        => kdcdump::convert(&data, &filename),
        "keystore"       => keystore_jks::convert(&data, &filename),
        "keplr"          => keplr::convert(&data, &filename),
        "kirbi"          => kirbi::convert(&data, &filename),
        "krb"            => krb::convert(&data, &filename),
        "kwallet"        => kwallet::convert(&data, &filename),
        "lotus"          => lotus::convert(&data, &filename),
        "prosody"        => prosody::convert(&data, &filename),
        "radius"         => radius::convert(&data, &filename),
        "sipdump"        => sipdump::convert(&data, &filename),
        _ => None,
    }
}

/// Returns all known converter names.
pub fn all_names() -> &'static [&'static str] {
    &[
        "ansible", "atmail", "bitcoin", "bitlocker", "bitwarden", "blockchain",
        "cisco", "dmg", "electrum", "encfs", "ethereum", "ios", "keepass",
        "lastpass", "ldif", "lion", "luks", "mac", "mongodb", "mozilla",
        "netntlm", "network", "office", "1password", "pcap", "pdf", "pgpdisk",
        "pgpsda", "pgpwde", "pwsafe", "sap", "7z", "signal", "ssh", "telegram",
        "truecrypt", "vdi", "veracrypt", "zed",
        "androidbackup", "androidfde", "axcrypt", "bestcrypt", "cardano",
        "coinomi", "dashlane", "deepsound", "diskcryptor", "dpapimk", "ecryptfs",
        "enpass", "fvde", "geli", "htdigest", "hccapx", "iwork", "keychain",
        "keyring", "known_hosts", "libreoffice", "monero", "multibit",
        "openbsd_softraid", "openssl", "pem", "pfx", "restic", "staroffice",
        "strip", "tezos", "vmx",
        "aix", "andotp", "applenotes", "bks", "ccache", "ejabberd", "gitea",
        "ikescan", "kdcdump", "keystore", "keplr", "kirbi", "krb", "kwallet",
        "lotus", "prosody", "radius", "sipdump",
    ]
}
