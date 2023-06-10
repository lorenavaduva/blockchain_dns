#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod dns {
    //use ink::storage::{Mapping, traits::StorageLayout};
    use ink::storage::Mapping;
    use scale_info::prelude::vec::Vec;
    use ink::storage::traits::StorageLayout;
    use scale_info::TypeInfo;

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode,TypeInfo)]
    pub enum DnsError {
        InvalidDomain,
        DomainAlreadyRegistered,
        DomainNotRegistered,
        SubdomainAlreadyRegistered,
        SubdomainNotRegistered,
        NotAuthorized,
    }

    #[ink(storage)]
    pub struct Dns {
        domain_map: Mapping<Vec<u8>,DomainData>,
        // subdomains: Mapping<(AccountId,SubdomainData), ()>
    }
    #[derive(scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct DomainData {
        owner: AccountId,
        ip_address: Vec<u8>,
        subdomains: Vec<SubdomainData>,
        
    }
    #[derive(scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct SubdomainData {
        subdomain: Vec<u8>,
        //ip_address: [u8; 4],//modify
        ip_address: Vec<u8>    
    }

    impl Dns {

        //create defaults for domain and domaindata ?
        #[ink(constructor)]
        pub fn new() -> Self {
            // let mut int_domain_map = Mapping::new();
            // let mut int_subdomain_map = Mapping::new();
            // let mut vec = Vec::<u8>::new();
            // vec.push(0u8);

            // let subdomain_data = SubdomainData {
            //     owner: Self::zero_address(),
            //     ip_address:vec.clone(),
            // };
            // int_subdomain_map.insert(vec, &subdomain_data);
            // let domain_data = DomainData {
            //     owner: Self::zero_address(),
            //     ip_address: vec.clone(),
            //     subdomains: int_subdomain_map
            // };

            // int_domain_map.insert(vec, &domain_data);

            Self {
                domain_map: Self::default_domain()
            }
        }

        fn zero_address() -> AccountId {
            [0u8; 32].into()
        }

        fn default_domain() -> Mapping<Vec<u8>,DomainData> {
            let mut int_domain_map = Mapping::new();
            let mut vec = Vec::<u8>::new();
            vec.push(0u8);

            let domain_data = DomainData {
                owner: Self::zero_address(),
                ip_address: vec.clone(),
                subdomains: Self::default_subdomain()
            };
            int_domain_map.insert(vec, &domain_data);
            return int_domain_map;
        }

        fn default_subdomain() -> Mapping<(AccountId,SubdomainData), ()>{

            let mut int_subdomain_map = Mapping::new();
            let mut vec = Vec::<u8>::new();
            vec.push(0u8);

            let subdomain_data = SubdomainData {
                owner: Self::zero_address(),
                ip_address:vec.clone(),
            };

            int_subdomain_map.insert(vec, &subdomain_data);
            return int_subdomain_map;
        }

        pub fn default(&self)   {
            
        }
        // #[ink(message)]
        // pub fn register_domain(&mut self, domain: u8, ip_address: u8) {
        //     self.domain_map.insert(domain, &ip_address);
        // }

        #[ink(message)]
        pub fn register_domain(
            &mut self,
            domain: Vec<u8>,
            ip_address: Vec<u8>,
        ) -> Result<(), DnsError> {
            let caller = self.env().caller();
            if self.domain_map.contains(&domain) {
                return Err(DnsError::DomainAlreadyRegistered);
            }
            let domain_data = DomainData {
                owner: caller,
                ip_address,
                subdomains: Default::default(),
            };
            self.domain_map.insert(domain, &domain_data);
            Ok(())
        }


        // #[ink(message)]
        // pub fn unregister_domain(&mut self, domain: u8) {
        //     self.domain_map.remove(domain);
        // }
        #[ink(message)]
        pub fn unregister_domain(&mut self, domain: Vec<u8>) -> Result<(), DnsError> {
            let caller = self.env().caller();
            if !self.domain_map.contains(&domain) {
                return Err(DnsError::DomainNotRegistered);
            }
            if self.domain_map.get(&domain).map(|data| data.owner) != Some(caller) {
                return Err(DnsError::NotAuthorized);
            }
            
            self.domain_map.remove(&domain); //here, only the value is removed. The key remains. To add in the future a check for this
            Ok(())
        }

        // #[ink(message)]
        // pub fn resolve_domain(&self, domain: u8) -> u8 {
        //     self.domain_map.get(&domain).unwrap_or_default()
        // }

        #[ink(message)]
        pub fn resolve_domain(&self, domain: Vec<u8>) -> Option<Vec<u8>> {
            self.domain_map
                .get(&domain)
                .map(|data| data.ip_address.clone())
        }
    }
}
