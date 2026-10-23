// SPDX-License-Identifier: Apache-2.0

mod csv {
    use csv_rs::cached_chain;
    use csv_rs::{api::platform::Firmware, certs::Usage, Build, Version};

    use serial_test::serial;

    #[inline(always)]
    fn rm_cached_chain() {
        let paths = cached_chain::path();
        if let Some(path) = paths.first() {
            if path.exists() {
                std::fs::remove_file(path).unwrap();
            }
        }
    }

    #[cfg_attr(not(all(has_dev_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn platform_reset() {
        let mut fw = Firmware::open().unwrap();
        fw.platform_reset().unwrap();
        rm_cached_chain();
    }

    #[cfg_attr(not(has_dev_sev), ignore)]
    #[test]
    fn platform_status() {
        let mut fw = Firmware::open().unwrap();
        let status = fw.platform_status().unwrap();
        println!("{:?}", status.build);
        assert!(
            status.build
                > Build {
                    version: Version { major: 1, minor: 2 },
                    ..Default::default()
                }
        );
    }

    #[cfg_attr(not(all(has_dev_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn pek_generate() {
        let mut fw = Firmware::open().unwrap();
        fw.pek_generate().unwrap();
        rm_cached_chain();
    }

    #[cfg_attr(not(has_dev_sev), ignore)]
    #[test]
    fn pek_csr() {
        let mut fw = Firmware::open().unwrap();
        let pek = fw.pek_csr().unwrap();
        assert_eq!(Usage::try_from(&pek).unwrap(), Usage::PEK);
    }

    #[cfg_attr(not(all(has_dev_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn pdh_generate() {
        let mut fw = Firmware::open().unwrap();
        fw.pdh_generate().unwrap();
        rm_cached_chain();
    }

    #[cfg_attr(not(has_dev_sev), ignore)]
    #[test]
    fn pdh_cert_export() {
        use csv_rs::certs::Verifiable;

        let mut fw = Firmware::open().unwrap();
        let chain = fw.pdh_cert_export().unwrap();

        assert_eq!(Usage::try_from(&chain.pdh).unwrap(), Usage::PDH);
        assert_eq!(Usage::try_from(&chain.pek).unwrap(), Usage::PEK);
        assert_eq!(Usage::try_from(&chain.oca).unwrap(), Usage::OCA);
        assert_eq!(Usage::try_from(&chain.cek).unwrap(), Usage::CEK);

        chain.verify().unwrap();
    }

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn pek_cert_import() {
        use csv_rs::certs::{csv::Certificate, Signer, Verifiable};

        let mut fw = Firmware::open().unwrap();

        let (mut oca, key) = Certificate::generate(Usage::OCA, None).unwrap();
        let uid = String::try_from(key.usage).unwrap();
        key.sign(&mut oca, uid.clone()).unwrap();

        let mut pek = fw.pek_csr().unwrap();
        key.sign(&mut pek, uid.clone()).unwrap();

        fw.pek_cert_import(&pek, &oca).unwrap();

        let chain = fw.pdh_cert_export().unwrap();
        // TODO: open it after eq is implement
        //assert_eq!(oca, chain.oca);
        chain.verify().unwrap();

        fw.platform_reset().unwrap();
    }

    #[cfg_attr(not(has_dev_sev), ignore)]
    #[test]
    fn get_identifier() {
        let mut fw = Firmware::open().unwrap();
        let id = fw.get_identifier().unwrap();
        assert_ne!(Vec::from(id), vec![0u8; 64]);
    }
}
