#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod dns {

    use ink::storage::Mapping;
    use scale_info::prelude::vec::Vec;
    use scale_info::TypeInfo;

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode,TypeInfo)]
    pub enum DnsError {
        // InvalidDomain,
        DomainAlreadyRegistered,
        DomainNotRegistered,
        SubdomainAlreadyRegistered,
        SubdomainNotRegistered,
        NotAuthorized,
    }

    #[ink(storage)]
    pub struct Dns {
        domain_map: Mapping<Vec<u8>,DomainData>
    }

    #[derive(scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct DomainData {
        owner: AccountId,
        ip_address: Vec<u8>,
        parent_domain: Option<Vec<u8>>  
    }

    impl Default for Dns {

        fn default() -> Self {
            let mut int_domain_map = Mapping::new();
            let mut vec = Vec::<u8>::new();
            vec.push(0u8);

            let domain_data = DomainData {
                owner: Self::zero_address(),
                ip_address: vec.clone(),
                parent_domain: None
            };
            int_domain_map.insert(vec, &domain_data);
            Self{
                domain_map: int_domain_map
            }
        }
    }
    impl Dns {

        #[ink(constructor)]
        pub fn new() -> Self {
            Default::default()
        }

        fn zero_address() -> AccountId {
            [0u8; 32].into()
        }

        #[ink(message)]
        pub fn register_domain(
            &mut self,
            domain: Vec<u8>,
            ip_address: Vec<u8>,
        ) -> Result<(), DnsError> {
            ink_env::debug_println!("pula");
            let caller = self.env().caller();
            if self.domain_map.contains(&domain) {
                ink_env::debug_println!("Domain is already registered");
                return Err(DnsError::DomainAlreadyRegistered);
            }
            let domain_data = DomainData {
                owner: caller,
                ip_address,
                parent_domain: None
            };
            let domain_for_debug = domain.clone(); 
            self.domain_map.insert(domain, &domain_data);
            ink_env::debug_println!("Domain was successfully registered: {:?}", core::str::from_utf8(&domain_for_debug));
            Ok(())
        }

        #[ink(message)]
        pub fn register_subdomain(
            &mut self,
            subdomain: Vec<u8>,
            parent_domain: Vec<u8>,
            ip_address: Vec<u8>,
        ) -> Result<(), DnsError> {
            let caller = self.env().caller();

            if !self.domain_map.contains(&parent_domain) {
                return Err(DnsError::DomainNotRegistered);
            }

            if self.domain_map.get(&parent_domain).map(|data| data.owner) != Some(caller) {
                return Err(DnsError::NotAuthorized);
            }

            if self.domain_map.contains(&subdomain) {
                return Err(DnsError::SubdomainAlreadyRegistered);
            }

            let domain_data = DomainData {
                owner: caller,
                ip_address,
                parent_domain: Some(parent_domain),
            };
            self.domain_map.insert(subdomain, &domain_data);
            Ok(())
        }
        
        #[ink(message)]
        pub fn unregister_subdomain(&mut self, subdomain: Vec<u8>) -> Result<(), DnsError> {
            let caller = self.env().caller();
            if !self.domain_map.contains(&subdomain) {
                return Err(DnsError::SubdomainNotRegistered);
            }
            if self.domain_map.get(&subdomain).map(|data| data.owner) != Some(caller) {
                return Err(DnsError::NotAuthorized);
            }
            self.domain_map.remove(&subdomain); 
            Ok(())
        }
        
        #[ink(message)]
        pub fn unregister_domain(&mut self, domain: Vec<u8>) -> Result<(), DnsError> {
            let caller = self.env().caller();
            if !self.domain_map.contains(&domain) {
                return Err(DnsError::DomainNotRegistered);
            }
            if self.domain_map.get(&domain).map(|data| data.owner) != Some(caller) {
                return Err(DnsError::NotAuthorized);
            }
            
            self.domain_map.remove(&domain); 
            Ok(())
        }

        #[ink(message)]
        pub fn resolve_domain(&self, domain: Vec<u8>) -> Option<Vec<u8>> {
            self.domain_map
                .get(&domain)
                .map(|data| data.ip_address.clone())
        }
    }



    #[cfg(test)]
    mod tests {
        use super::*;

        fn default_accounts(
        ) -> ink::env::test::DefaultAccounts<ink::env::DefaultEnvironment> {
            ink::env::test::default_accounts::<Environment>()
        }

        fn set_next_caller(caller: AccountId) {
            ink::env::test::set_caller::<Environment>(caller);
        }

        #[ink::test]
        fn test_register_domain() {
            let mut contract = Dns::new();
            let domain = b"example.org".to_vec();
            let ip_address = b"192.168.0.1".to_vec();
            let non_existent_domain = b"nonexistent.org".to_vec();
            assert_eq!(contract.register_domain(domain.clone(), ip_address.clone()), Ok(()));
            assert_eq!(contract.resolve_domain(non_existent_domain), None);
            assert_eq!(contract.register_domain(domain.clone(), ip_address.clone()), Err(DnsError::DomainAlreadyRegistered));
        }

        #[ink::test]
        fn test_unregister_domain() {
            let mut contract = Dns::new();
            let domain = b"example.org".to_vec();
            let ip_address = b"192.168.0.1".to_vec();
            let accounts = default_accounts();
            let non_existent_domain = b"nonexistent.org".to_vec();
        
            //Domain not registered case
            assert_eq!(contract.unregister_domain(non_existent_domain.clone()), Err(DnsError::DomainNotRegistered));
            //Unregister a domain when not authorized
            set_next_caller(accounts.alice);
            assert_eq!(contract.register_domain(domain.clone(), ip_address.clone()), Ok(()));
            set_next_caller(accounts.bob);
            assert_eq!(contract.unregister_domain(domain.clone()), Err(DnsError::NotAuthorized));
            //Unregister the domain by the owner.
            set_next_caller(accounts.alice);
            assert_eq!(contract.unregister_domain(domain.clone()), Ok(()));
            assert_eq!(contract.resolve_domain(domain.clone()), None);
        }

        #[ink::test]
        fn test_register_subdomain() {
            let mut contract = Dns::new();
            let parent_domain = b"example.org".to_vec();
            let subdomain = b"shop.example.org".to_vec();
            let ip_address = b"192.168.0.1".to_vec();
            let accounts = default_accounts();
            set_next_caller(accounts.alice);

            // Cannot register subdomain before registering the parent domain.
            assert_eq!(contract.register_subdomain(subdomain.clone(), parent_domain.clone(), ip_address.clone()), Err(DnsError::DomainNotRegistered));

            // Register the parent domain.
            assert_eq!(contract.register_domain(parent_domain.clone(), ip_address.clone()), Ok(()));

            // Register the subdomain.
            assert_eq!(contract.register_subdomain(subdomain.clone(), parent_domain.clone(), ip_address.clone()), Ok(()));

            // Subdomain is already registered.
            assert_eq!(contract.register_subdomain(subdomain.clone(), parent_domain.clone(), ip_address.clone()), Err(DnsError::SubdomainAlreadyRegistered));

            // Cannot register subdomain for a domain owned by another user.
            set_next_caller(accounts.bob);
            let other_subdomain = b"news.example.org".to_vec();
            assert_eq!(contract.register_subdomain(other_subdomain.clone(), parent_domain.clone(), ip_address.clone()), Err(DnsError::NotAuthorized));
        }

        #[ink::test]
        fn test_unregister_subdomain() {
            let mut contract = Dns::new();
            let parent_domain = b"example.org".to_vec();
            let subdomain = b"shop.example.org".to_vec();
            let ip_address = b"192.168.0.1".to_vec();
            let accounts = default_accounts();
            set_next_caller(accounts.alice);

            // Register the parent domain and subdomain.
            assert_eq!(contract.register_domain(parent_domain.clone(), ip_address.clone()), Ok(()));
            assert_eq!(contract.register_subdomain(subdomain.clone(), parent_domain.clone(), ip_address.clone()), Ok(()));

            // Subdomain is not registered.
            let non_existent_subdomain = b"nonexistent.example.org".to_vec();
            assert_eq!(contract.unregister_subdomain(non_existent_subdomain.clone()), Err(DnsError::SubdomainNotRegistered));

            // Cannot unregister a subdomain owned by another user.
            set_next_caller(accounts.bob);
            assert_eq!(contract.unregister_subdomain(subdomain.clone()), Err(DnsError::NotAuthorized));

            // Unregister the subdomain.
            set_next_caller(accounts.alice);
            assert_eq!(contract.unregister_subdomain(subdomain.clone()), Ok(()));
            assert_eq!(contract.resolve_domain(subdomain.clone()), None);
        }

        #[ink::test]
        fn test_resolve_subdomain() {
            let mut contract = Dns::new();
            let parent_domain = b"example.org".to_vec();
            let subdomain = b"shop.example.org".to_vec();
            let ip_address = b"192.168.0.1".to_vec();
            let accounts = default_accounts();
            set_next_caller(accounts.alice);

            // Register the parent domain and subdomain.
            assert_eq!(contract.register_domain(parent_domain.clone(), ip_address.clone()), Ok(()));
            assert_eq!(contract.register_subdomain(subdomain.clone(), parent_domain.clone(), ip_address.clone()), Ok(()));

            // Resolve the subdomain.
            assert_eq!(contract.resolve_domain(subdomain.clone()), Some(ip_address.clone()));
        }


        
    }
}

