#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod dns {
    //use ink::storage::{Mapping, traits::StorageLayout};
    use ink::storage::Mapping;
    //use ink_storage_traits::StorageLayout;
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
    #[derive(Default)]
    pub struct Dns {
        // domain_map: Mapping<Vec<u8>,DomainData>,
        domain_map: Mapping<u8,u8>,
    }

    // #[derive(Debug,scale::Encode, scale::Decode,StorageLayout,TypeInfo)]
    // pub struct DomainData {
    //     owner: AccountId,
    //     ip_address: Vec<u8>,
    // }

    impl Dns {


        #[ink(constructor)]
        pub fn new() -> Self {
            Dns::default()
        }

        #[ink(message)]
        pub fn register_domain(&mut self, domain: u8, ip_address: u8) {
            self.domain_map.insert(domain, &ip_address);
        }

        // #[ink(message)]
        // pub fn register_domain(
        //     &mut self,
        //     domain: Vec<u8>,
        //     ip_address: Vec<u8>,
        // ) -> Result<(), DnsError> {
        //     let caller = self.env().caller();
        //     if self.domain_map.contains(&domain) {
        //         return Err(DnsError::DomainAlreadyRegistered);
        //     }
        //     let domain_data = DomainData {
        //         owner: caller,
        //         ip_address,
        //         // subdomains: Default::default(),
        //     };
        //     self.domain_map.insert(domain, &domain_data);
        //     Ok(())
        // }


        #[ink(message)]
        pub fn unregister_domain(&mut self, domain: u8) {
            self.domain_map.remove(domain);
        }
        // #[ink(message)]
        // pub fn unregister_domain(&mut self, domain: Vec<u8>) -> Result<(), DnsError> {
        //     let caller = self.env().caller();
        //     if !self.domain_map.contains(&domain) {
        //         return Err(DnsError::DomainNotRegistered);
        //     }
        //     if self.domain_map.get(&domain).map(|data| data.owner) != Some(caller) {
        //         return Err(DnsError::NotAuthorized);
        //     }
            
        //     self.domain_map.remove(&domain); //here, only the value is removed. The key remains. To add in the future a check for this
        //     Ok(())
        // }

        #[ink(message)]
        pub fn resolve_domain(&self, domain: u8) -> u8 {
            self.domain_map.get(&domain).unwrap_or_default()
        }

        // #[ink(message)]
        // pub fn resolve_domain(&self, domain: Vec<u8>) -> Option<Vec<u8>> {
        //     self.domain_map
        //         .get(&domain)
        //         .map(|data| data.ip_address.clone())
        // }
    }
}
