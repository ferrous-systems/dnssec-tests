use std::net::Ipv4Addr;

use dns_test::{
    client::{Client, DigSettings},
    name_server::NameServer,
    peer,
    record::{Record as R, RecordType},
    zone_file::Root,
    Network, Resolver, Result, TrustAnchor, FQDN,
};

/// Setup:
///   3 domains:
///   - a.example.com
///   - c.example.com
///   - x.example.com
///
/// When requesting a record for b.example.com it should return an NSEC3 record
/// with [a.example.com, c.example.com] interval.
#[ignore]
#[test]
fn proof_of_non_existence_with_nsec3_records() -> Result<()> {
    let network = &Network::new()?;
    let peer = &peer();
    let mut root_ns = NameServer::new(peer, FQDN::ROOT, network)?;
    let mut com_ns = NameServer::new(peer, FQDN::COM, network)?;

    let mut example_ns = NameServer::new(peer, FQDN("example.com.")?, network)?;
    let example_ns_ip = Ipv4Addr::new(192, 0, 2, 1);

    example_ns
        .add(R::a(FQDN("a.example.com.")?, Ipv4Addr::new(1, 2, 3, 4)))
        .add(R::a(FQDN("c.example.com.")?, Ipv4Addr::new(1, 2, 3, 5)))
        .add(R::a(FQDN("x.example.com.")?, Ipv4Addr::new(1, 2, 3, 6)));

    let example_ns = example_ns.sign()?;
    let example_ds = example_ns.ds().clone();
    let example_ns = example_ns.start()?;

    let mut nameservers_ns = NameServer::new(peer, FQDN("nameservers.com.")?, network)?;
    nameservers_ns
        .add(R::a(root_ns.fqdn().clone(), root_ns.ipv4_addr()))
        .add(R::a(com_ns.fqdn().clone(), com_ns.ipv4_addr()))
        .add(R::a(example_ns.fqdn().clone(), example_ns.ipv4_addr()));
    let nameservers_ns = nameservers_ns.start()?;

    eprintln!("nameservers.com.zone:\n{}", nameservers_ns.zone_file());

    com_ns.referral(
        nameservers_ns.zone().clone(),
        nameservers_ns.fqdn().clone(),
        nameservers_ns.ipv4_addr(),
    );

    com_ns
        .referral(
            example_ns.zone().clone(),
            example_ns.fqdn().clone(),
            example_ns_ip,
        )
        .add(R::DS(example_ds));
    let com_ns = com_ns.sign()?;
    let com_ds = com_ns.ds().clone();
    let com_ns = com_ns.start()?;

    root_ns
        .referral(FQDN::COM, com_ns.fqdn().clone(), com_ns.ipv4_addr())
        .add(R::DS(com_ds));
    let root_ns = root_ns.sign()?;
    let root_ksk = root_ns.key_signing_key().clone();
    let root_zsk = root_ns.zone_signing_key().clone();

    let root_ns = root_ns.start()?;

    let roots = &[Root::new(root_ns.fqdn().clone(), root_ns.ipv4_addr())];

    let trust_anchor = TrustAnchor::from_iter([root_ksk.clone(), root_zsk.clone()]);
    let resolver = Resolver::start(&dns_test::subject(), roots, &trust_anchor, network)?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(network)?;
    let settings = *DigSettings::default().recurse().authentic_data();

    let needle_fqdn = FQDN("b.example.com.")?;
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    let log = resolver.terminate()?;

    eprintln!("{}", log);

    eprintln!("{:?}", output);

    assert!(output.status.is_nxdomain());

    // assert!(output.flags.authenticated_data);

    Ok(())
}
