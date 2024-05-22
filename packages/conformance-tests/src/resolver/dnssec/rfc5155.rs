use std::net::Ipv4Addr;

use dns_test::{
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType, NSEC3},
    Network, Resolver, Result, FQDN,
};

/// Find the index of the element immediately previous to `needle` in `haystack`.
fn find_prev(needle: &str, haystack: &Vec<&str>) -> usize {
    assert!(!haystack.is_empty());

    let (Ok(index) | Err(index)) = haystack.binary_search(&needle);
    match index {
        0 => haystack.len() - 1,
        index => index - 1,
    }
}

/// Find the index of the element immediately next to `needle` in `haystack`.
fn find_next(needle: &str, haystack: &Vec<&str>) -> usize {
    assert!(!haystack.is_empty());

    let (Ok(index) | Err(index)) = haystack.binary_search(&needle);
    (index + 1) % haystack.len()
}

/// Return `true` if `record` convers `hash`. This is, if `hash` falls in between the owner of
/// `record` and the next hashed owner name of `record`.
fn covers(record: &NSEC3, hash: &str) -> bool {
    record.next_hashed_owner_name.as_str() > hash
        && record.fqdn.labels().next().unwrap().to_uppercase().as_str() < hash
}

#[test]
fn proof_of_non_existence_with_nsec3_records() -> Result<()> {
    let network = Network::new()?;

    let alice_fqdn = FQDN("alice.nameservers.com.")?;
    let bob_fqdn = FQDN("bob.nameservers.com.")?;
    let charlie_fqdn = FQDN("charlie.nameservers.com.")?;

    // To compute these hashes refer to [Section 5 of RFC 5515](https://datatracker.ietf.org/doc/html/rfc5155#section-5)
    // or install `dnspython` and then run:
    //
    // ```python
    // import dns.dnssec
    //
    // dns.dnssec.nsec3_hash(domain, salt="", iterations=1, algorithm="SHA1")
    // ```
    let bob_hash = "9AU9KOU2HVABPTPB7D3AQBH57QPLNDI6"; /* bob.namesevers.com. */
    let wildcard_hash = "M417220KKVJDM7CHD6QVUV4TGHDU2N2K"; /* *.nameservers.com */
    let nameservers_hash = "7M2FCI51VUC2E5RIBDPTVJ6S08EMMR3O"; /* nameservers.com. */

    let mut leaf_ns = NameServer::new(&dns_test::PEER, FQDN::NAMESERVERS, &network)?;
    leaf_ns
        .add(Record::a(alice_fqdn.clone(), Ipv4Addr::new(1, 2, 3, 4)))
        .add(Record::a(charlie_fqdn.clone(), Ipv4Addr::new(1, 2, 3, 5)));

    let Graph {
        nameservers,
        root,
        trust_anchor,
    } = Graph::build(leaf_ns, Sign::Yes)?;

    // This is the sorted list of hashes that can be proven to exist by the name servers.
    let hashes = {
        // These are the hashes that we statically know they exist.
        let mut hashes = vec![
            nameservers_hash,
            "8C538GR0B1FT11G01UI8THM4IPM64NUC", /* charlie.nameservers.com. */
            "PQVTTO5UIDVCHKP34DDQ3LIIH7TQED20", /* alice.nameservers.com. */
        ];

        // Include the hashes of the nameservers dynamically as they change between executions.
        for ns in &nameservers {
            let hash = match ns.fqdn().as_str() {
                "primary0.nameservers.com." => "E05P5R80N590NS9PP24QOOFHRT605T8A",
                "primary1.nameservers.com." => "C1JIVO7U1IH8JFK6BMU60V65S5FVEFT2",
                "primary2.nameservers.com." => "NJ1OLIA8A6HTNBMC20ATDDIDTA42AI8V",
                "primary3.nameservers.com." => "9JMUC5ADM6MUKUN4NTBMR19C1030SRM0",
                "primary4.nameservers.com." => "0RM17SJJI0C51PADDIFG9LI8K2S04EE9",
                "primary5.nameservers.com." => "546PPSKSPN8DOKTTA9MASB0TM06I72GD",
                "primary6.nameservers.com." => "40PTL9S01ERIF3E05RERHM419K0465GB",
                "primary7.nameservers.com." => "G8O54KH0MJNTDE1IFQOBSLNRA5G7PGJ0",
                "primary8.nameservers.com." => "FRMTGMJ1QH91I2QHU61BTJNFKS39UQ2D",
                "primary9.nameservers.com." => "6RJVT7UR167JB2296JTV2VG9P8LJK1KG",
                "primary10.nameservers.com." => "1CN3HD3QPK3R53P3L13FL91KSML0LT13",
                "primary11.nameservers.com." => "6TEE5C0TA2FU4T2KA9R3CT749IVDH0R2",
                "primary12.nameservers.com." => "0DJ0I4F1D7AANKJQ5RB9CLFSALMC636P",
                "primary13.nameservers.com." => "QBHIT7FBP5GM6K1NPK23KIKFRFLESB59",
                "primary14.nameservers.com." => "OAIN54SNHJ76M5ATNE9U21DMVC0QIU6L",
                ns => panic!("Unexpected nameserver: {ns}"),
            };

            hashes.push(hash);
        }

        // Sort the hashes
        hashes.sort();
        hashes
    };

    let trust_anchor = &trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(trust_anchor)
        .start(&dns_test::SUBJECT)?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data().dnssec();

    let output = client.dig(settings, resolver_addr, RecordType::MX, &bob_fqdn)?;

    assert!(output.status.is_nxdomain());

    let nsec3_rrs = output
        .authority
        .into_iter()
        .filter_map(|record| {
            if let Record::NSEC3(r) = record {
                Some(r)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for record in &nsec3_rrs {
        // Check that the hashing function is SHA-1.
        assert_eq!(record.hash_alg, 1);
        // Check that the salt is empty (dig puts `-` in the salt field when it is empty).
        assert_eq!(record.salt, "-");
        // Check that the number of iterations is 1. 
        assert_eq!(record.iterations, 1);
    }

    // Closest encloser RR: Must match the closest encloser of bob.nameservers.com.
    //
    // The closest encloser must be nameservers.com. as it is the closest existing ancestor of
    // bob.nameservers.com.
    let closest_encloser_fqdn = FQDN(nameservers_hash.to_lowercase() + ".nameservers.com.")?;
    let closest_encloser_rr = nsec3_rrs
        .iter()
        .find(|record| record.fqdn == closest_encloser_fqdn)
        .expect("Closest encloser RR was not found");

    // Check that the next hashed owner name of the record is the hash immediately next to the hash
    // of nameservers.com.
    let expected = hashes[find_next(nameservers_hash, &hashes)];
    let found = &closest_encloser_rr.next_hashed_owner_name;
    assert_eq!(expected, found);

    // Next closer name RR: Must cover the next closer name of bob.nameservers.com.
    //
    // The next closer name of bob.nameservers.com. is bob.nameservers.com. as it is the name one
    // label longer than nameservers.com.
    let next_closer_name_rr = nsec3_rrs
        .iter()
        .find(|record| covers(record, bob_hash))
        .expect("Closest encloser RR was not found");

    let index = find_prev(bob_hash, &hashes);

    // Check that the owner hash of record is the hash immediately previous to the hash of
    // bob.nameservers.com.
    let expected = hashes[index];
    let found = next_closer_name_rr
        .fqdn
        .labels()
        .next()
        .unwrap()
        .to_uppercase();
    assert_eq!(expected, found);

    // Check that the next hashed owner name of the record is the hash immediately next to the
    // owner hash.
    let expected = hashes[(index + 1) % hashes.len()];
    let found = &next_closer_name_rr.next_hashed_owner_name;
    assert_eq!(expected, found);

    // Wildcard at the closet encloser RR: Must cover the wildcard at the closest encloser of
    // bob.nameservers.com.
    //
    // The wildcard at the closest encloser of bob.nameservers.com. is *.nameservers.com. as it is
    // the wildcard at nameservers.com.
    let wildcard_rr = nsec3_rrs
        .iter()
        .find(|record| covers(record, wildcard_hash))
        .expect("Wildcard RR was not found");

    let index = find_prev(wildcard_hash, &hashes);

    // Check that the owner hash of record is the hash immediately previous to the hash of
    // *.nameservers.com.
    let expected = hashes[index];
    let found = wildcard_rr.fqdn.labels().next().unwrap().to_uppercase();
    assert_eq!(expected, found);

    // Check that the next hashed owner name of the record is the hash immediately next to the
    // owner hash.
    let expected = hashes[(index + 1) % hashes.len()];
    let found = &wildcard_rr.next_hashed_owner_name;
    assert_eq!(expected, found);

    Ok(())
}
