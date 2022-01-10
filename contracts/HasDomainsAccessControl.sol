// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

import "./SafeOwnable.sol";
import "./HasManagers.sol";
import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";

/**
 * Domain access control is defined here. It involves some roles being defined,
 * some lists and lookups detailing default permissions, and a hierarchy that
 * is enforced privately across 3 defined roles in access-control traits:
 * general management, per-TLD management, and domain registrant.
 */
abstract contract HasDomainsAccessControl is SafeOwnable, HasManagers, AccessControlEnumerable {
    /**
     * Managers in this role will have permissions (inside a specific TLD they
     * are authorized to) to perform the following actions:
     * - Add a new domain (or recover a released domain, under their responsibility).
     * - Release a domain they are responsible for.
     * - Transfer a domain they are responsible for (the target must not be address(0)
     *   and also they must be in either specific-TLD registrant in the same TLD,
     *   or any-TLD registrant).
     * Every manager / admin will belong to either a specific TLD or belong to the
     * default list, and have this role. In the former case, typically one or more TLDs
     * will be assigned to them.
     *
     * An entry relating (tld, address) => {add, release, transfer} may modify the
     * permissions the address has inside this tld. By default, a user in this role
     * will have no permissions over a given TLD unless the TLD has an entry for it,
     * being the entry the one which enables the action by setting it to true.
     *
     * However, if the address also is enabled into the defaultDomainRegistrants set
     * then the default permissions when lacking an entry for a given TLD, is to have
     * permissions to do any of the 3 actions in the TLD.
     *
     * The TLD configuration, for the involved domain, may however have their own
     * flags {add, release, transfer} in false (they default in true), thus blocking
     * the required action despite the address being among the default registrants.
     * When this happens, only the contract owner or an address in the tld manager
     * role (described way below) can handle them.
     */
    bytes32 public domainRegistrantRole;

    /**
     * Tells whether a particular address belongs to the default domain registrants
     * set or not. To add an entry, assign it to true. To remove an entry, assign it
     * to false. Entries are not definitely removed, ever, but they may be disabled.
     * In order to be added to this set, an entry must exist as a manager entry from
     * the managers trait.
     */
    mapping(address => bool) public defaultDomainRegistrants;

    /**
     * Tells the whole list of addresses eventually added to the defaultDomainRegistrants
     * mapping (even if they were removed later). Meant for enumeration.
     */
    address[] public defaultDomainRegistrantsList;

    /**
     * Returns the length of the defaultDomainRegistrantsList. Meant for enumeration.
     */
    function defaultDomainRegistrantsCount() public view returns (uint256) {
        return defaultDomainRegistrantsList.length;
    }

    /**
     * Managers in this role can handle their TLD completely, including:
     * - The three actions of domainRegistrantRole, over their own domains.
     *   This is because they will also have this role: domainRegistrantRole.
     * - The same three actions over domains they are not responsible of, but
     *   others are, except when the other one also belongs to tldManagerRole.
     *   They are not restricted by the per-TLD restrictions, and they ignore
     *   their own entry in the TLD related to their domainRegistrantRole, if
     *   they ever have / had one.
     * - The ability to change the said per-TLD restrictions.
     * - The ability to add addresses (provided they have the domainRegistrantRole)
     *   to the TLD or TLDs they manage, or change their per-address permissions.
     */
    bytes32 public tldManagerRole;

    /**
     * Tells whether a particular address belongs to the default TLD managers
     * or not. To add an entry, assign it to true. To remove an entry, assign
     * it to false. Entries are not definitely removed, ever, but they may be
     * disabled. In order to be added to this set, an entry must exist as a
     * manager entry from the managers trait.
     */
    mapping(address => bool) defaultTLDManagers;

    /**
     * Tells the whole list of addresses eventually added to the defaultTLDManagers
     * mapping (even if they were removed later). Meant for enumeration.
     */
    address[] public defaultTLDManagersList;

    /**
     * Returns the length of the defaultTLDManagersList. Meant for enumeration.
     */
    function defaultTLDManagersCount() public view returns (uint256) {
        return defaultTLDManagersList.length;
    }

    /**
     * Manager in this role will also include the tldManagerRole and also the
     * domainRegistrantRole (notice how this role name says "tlds", in plural).
     * Aside from the other said permissions, they are not restricted by other
     * users' roles. This role is typically intended for really trusted users.
     * They can CREATE a TLD, not just change their permissions or set registrants
     * into it / modify their per-address permissions.
     *
     * They have direct access to ALL of the TLDs, in contrast to the previous
     * two roles, and they can add addresses (provided they have the tldManagerRole)
     * as managers to certain TLDs, or as default TLDs managers. Also, they can
     * add addresses (provided they have the domainRegistrantRole) as default
     * domain registrants (i.e. for all the TLDs).
     *
     * The only thing they CANNOT do, is to make new addresses become this role,
     * or existing addresses lose this role. That is reserved solely to the owner
     * of this contract, and such owner has all the permissions in this role and
     * the others, with no limitation of any type.
     */
    bytes32 public tldsManagerRole;

    constructor() {
        domainRegistrantRole = keccak256(abi.encodePacked("Access Role", "Domain Registrant"));
        tldManagerRole = keccak256(abi.encodePacked("Access Role", "TLD Manager"));
        tldsManagerRole = keccak256(abi.encodePacked("Access Role", "TLDs Manager"));
    }

    // Notes: Only query functions that ask for permissions will be coded here. Also,
    //        some abstract methods will be added -which interact with more data- which
    //        will be overridden later.

    /**
     * Tells whether the account is a TLDs manager (i.e. a global, trusted user, who
     * can do anything on registered TLDs or even create one).
     */
    function isTLDsManager(address who) public view returns (bool) {
        return who != address(0) && hasRole(tldsManagerRole, who);
    }

    /**
     * Tells whether the account is a specific TLD manager (i.e. a default TLD manager
     * for any TLD, or a registered TLD manager for a specific TLD).
     */
    function isTLDManager(bytes32 tldHash, address who) public view returns (bool) {
        return who != address(0) && hasRole(tldManagerRole, who) && (defaultTLDManagers[who] ||
                                                                     managesTheTLD(tldHash, who));
    }

    /**
     * Tells whether the account is registered as a manager related to a specific TLD hash.
     * To this point, it is known that the address is not 0x0 and it HAS the tld manager role.
     * Override it to specify the particular behaviour.
     */
    function managesTheTLD(bytes32 tldHash, address who) internal view virtual returns (bool);

    /**
     * Tells whether the account is registered as a domain registrant to a specific TLD hash.
     * The check will involve, first, an explicit permission check (which asks for specific
     * flags allowing/disallowing the account to add, release or transfer a domain).
     */
    function isDomainRegistrant(
        bytes32 tldHash, address who,
        bool requireAdd, bool requireRelease, bool requireTransfer
    ) public view returns (bool) {
        if (who != address(0) && hasRole(domainRegistrantRole, who)) {
            // 1. We rely on the address having an explicit permission in the TLD setting. If an
            //    explicit permission is set, then we check that the required flags are true in
            //    the permissions, if any is required.
            (bool explicit, bool canAdd, bool canRelease, bool canTransfer) = hasExplicitTLDPermission(tldHash, who);
            if (explicit) {
                return (canAdd && !requireAdd) && (canRelease || !requireRelease) && (canTransfer || !requireTransfer);
            }

            // 2. Otherwise, we rely on the address belonging to the defaultDomainRegistrants.
            return defaultDomainRegistrants[who];
        } else {
            return false;
        }
    }

    /**
     * Tells whether an address is explicitly registered into a TLD. If it has an explicit
     * setting, then the 3 flags must also be returned as the result value, with the first
     * value being true. Otherwise, the first value must be false, and the 3 other result
     * values don't matter.
     */
    function hasExplicitTLDPermission(
        bytes32 tldHash, address who
    ) public view virtual returns (bool explicit, bool canAdd, bool canRelease, bool canTransfer);
}
